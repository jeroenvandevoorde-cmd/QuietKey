//! Deterministic HOST reference for the ratified v1 provisioning mathematics.
//!
//! HOST REFERENCE ONLY — NOT PRODUCTION CRYPTOGRAPHY — NOT A WALLET —
//! NO ENTROPY, CARD, CEREMONY, TARGET, PERFORMANCE, OR GATE CLAIM.
//!
//! Inputs are caller-supplied deterministic bytes. Secret-bearing
//! intermediates are private fixed-size owners and public results contain only
//! xpubs, descriptors, wallet identity, first scripts/addresses, and A1.

#![deny(unsafe_code)]

mod bech32;
mod bip32_private;
mod bip39;
mod descriptor_build;
mod dice;
mod hkdf_sha256;
mod hmac_sha256;
mod hmac_sha512;
mod qkec;
mod ripemd160;
mod secret;
mod sha256;
mod sha512;

use bip32_private::derive_account;
use core::fmt;
use descriptor_build::{build_wallet, WalletPublic};
use secret::Secret;

/// Closed failure surface for M26 provisioning mathematics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningError {
    InvalidRecordLength,
    UnsupportedRecordVersion,
    UnknownSource,
    SourceOutOfOrder,
    DuplicateSource,
    InvalidSourceLength,
    MissingRequiredSource,
    SourceSetReuse,
    InvalidDiceSymbol,
    DiceCount,
    TranscriptReuse,
    InvalidMasterScalar,
    InvalidChildTweak,
    ZeroChild,
    CryptographicBackend,
    CryptographicInvariant,
    GeneratedDescriptorInvalid,
    NonceReuse,
    AlreadyEncrypted,
}

impl fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidRecordLength => "invalid QKEC record length",
            Self::UnsupportedRecordVersion => "unsupported QKEC record version",
            Self::UnknownSource => "unknown QKEC source",
            Self::SourceOutOfOrder => "QKEC source out of order",
            Self::DuplicateSource => "duplicate QKEC source",
            Self::InvalidSourceLength => "invalid QKEC source length",
            Self::MissingRequiredSource => "missing required QKEC source",
            Self::SourceSetReuse => "QKEC source set reused across purposes",
            Self::InvalidDiceSymbol => "invalid dice symbol",
            Self::DiceCount => "dice transcript must contain exactly 100 symbols",
            Self::TranscriptReuse => "dice transcript reused across purposes",
            Self::InvalidMasterScalar => "invalid BIP32 master scalar",
            Self::InvalidChildTweak => "invalid BIP32 child tweak",
            Self::ZeroChild => "BIP32 child scalar is zero",
            Self::CryptographicBackend => "cryptographic backend failure",
            Self::CryptographicInvariant => "cryptographic invariant failure",
            Self::GeneratedDescriptorInvalid => "generated descriptor failed strict reparse",
            Self::NonceReuse => "A1 nonce reused within provisioning run",
            Self::AlreadyEncrypted => "A1 capsule already created",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ProvisioningError {}

/// Complete public artifacts from one deterministic HOST provisioning run.
///
/// Every field is public wallet metadata. No entropy, mnemonic, seed, scalar,
/// chain code, xprv, source record, transcript, PRK, or IKM is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningArtifacts {
    pub account_xpubs: [[u8; 111]; 3],
    pub descriptors: [[u8; 445]; 2],
    pub wallet_id: [u8; 32],
    pub first_scripts: [[u8; 34]; 2],
    pub first_addresses: [[u8; 62]; 2],
    pub a1_capsule: [u8; 67],
}

/// One HOST provisioning run with an explicit within-run nonce-reuse boundary.
///
/// This type deliberately implements no `Clone`, `Copy`, `Debug`, or display
/// trait because it owns transient Seed-A and A2 bytes.
pub struct HostProvisioningRun {
    seed_a: Secret<32>,
    a2: Secret<32>,
    account_xpubs: [[u8; 111]; 3],
    wallet: WalletPublic,
    nonce: Option<[u8; 12]>,
}

impl HostProvisioningRun {
    fn from_secrets(secrets: [Secret<32>; 4]) -> Result<Self, ProvisioningError> {
        let [seed_a, signer_b, signer_c, a2] = secrets;

        let seed_a_bip39 = bip39::entropy_to_seed(seed_a.as_bytes())?;
        let account_a = derive_account(seed_a_bip39.as_bytes())?;
        drop(seed_a_bip39);

        let signer_b_bip39 = bip39::entropy_to_seed(signer_b.as_bytes())?;
        let account_b = derive_account(signer_b_bip39.as_bytes())?;
        drop(signer_b_bip39);
        drop(signer_b);

        let signer_c_bip39 = bip39::entropy_to_seed(signer_c.as_bytes())?;
        let account_c = derive_account(signer_c_bip39.as_bytes())?;
        drop(signer_c_bip39);
        drop(signer_c);

        let account_xpubs = [account_a.xpub, account_b.xpub, account_c.xpub];
        let wallet = build_wallet([account_a, account_b, account_c])?;
        Ok(Self {
            seed_a,
            a2,
            account_xpubs,
            wallet,
            nonce: None,
        })
    }

    /// Build one run from four separately owned canonical QKEC-1 records.
    pub fn from_qkec(
        records: [&[u8]; 4],
        ceremony_id: &[u8; 16],
    ) -> Result<Self, ProvisioningError> {
        Self::from_secrets(qkec::condition_four(records, ceremony_id)?)
    }

    /// Build one run from four exact 100-symbol Advanced-mode transcripts.
    pub fn from_dice(transcripts: [&[u8]; 4]) -> Result<Self, ProvisioningError> {
        Self::from_secrets(dice::digest_four(transcripts)?)
    }

    /// Encrypt Seed-A once and return the complete public artifact bundle.
    ///
    /// A repeated equal nonce is [`ProvisioningError::NonceReuse`]. A second
    /// attempt with any different nonce is [`ProvisioningError::AlreadyEncrypted`].
    pub fn encrypt_a1(
        &mut self,
        nonce: &[u8; 12],
    ) -> Result<ProvisioningArtifacts, ProvisioningError> {
        if let Some(previous) = self.nonce {
            return if previous == *nonce {
                Err(ProvisioningError::NonceReuse)
            } else {
                Err(ProvisioningError::AlreadyEncrypted)
            };
        }
        let capsule = qk_a1::encrypt(
            self.a2.as_bytes(),
            &self.wallet.wallet_id,
            nonce,
            self.seed_a.as_bytes(),
        );
        self.nonce = Some(*nonce);
        Ok(ProvisioningArtifacts {
            account_xpubs: self.account_xpubs,
            descriptors: self.wallet.descriptors,
            wallet_id: self.wallet.wallet_id,
            first_scripts: self.wallet.scripts,
            first_addresses: self.wallet.addresses,
            a1_capsule: capsule,
        })
    }
}

#[cfg(test)]
mod public_tests {
    use super::{HostProvisioningRun, ProvisioningError};

    #[test]
    fn same_run_nonce_state_is_fail_closed_and_cross_run_is_deliberately_accepted() {
        let transcripts = [[b'1'; 100], [b'2'; 100], [b'3'; 100], [b'4'; 100]];
        let refs = [
            &transcripts[0][..],
            &transcripts[1][..],
            &transcripts[2][..],
            &transcripts[3][..],
        ];
        let nonce = [0x42; 12];
        let other = [0x43; 12];

        let mut first = HostProvisioningRun::from_dice(refs).expect("public deterministic run");
        let artifacts = first.encrypt_a1(&nonce).expect("first encryption");
        assert_eq!(first.encrypt_a1(&nonce), Err(ProvisioningError::NonceReuse));
        assert_eq!(
            first.encrypt_a1(&other),
            Err(ProvisioningError::AlreadyEncrypted)
        );

        let mut second = HostProvisioningRun::from_dice(refs).expect("fresh run");
        assert_eq!(
            second.encrypt_a1(&nonce).expect("cross-run nonce accepted"),
            artifacts
        );
    }
}

#[cfg(test)]
mod fixture_tests;
