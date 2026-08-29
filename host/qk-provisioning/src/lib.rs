//! Deterministic HOST reference for the ratified v1 and v2 provisioning mathematics.
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
mod descriptor_build_v2;
mod dice;
mod hkdf_sha256;
mod hmac_sha256;
mod hmac_sha512;
mod kit_r;
mod kit_setup_v2;
mod qkec;
mod ripemd160;
mod secret;
mod sha256;
mod sha512;

use bip32_private::derive_account;
use core::fmt;
use descriptor_build::{build_wallet, WalletPublic};
use descriptor_build_v2::{build_wallet_v2, WalletPublicV2};
use secret::Secret;

pub use kit_setup_v2::{
    KitCopyV2, KitPageDispositionV2, KitPrintPageV2, KitSetupReceiptV2, KitShareIndexV2,
};

/// Closed failure surface for v1 and v2 HOST provisioning mathematics.
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
    A1NotReady,
    KitEncodingInvariant,
    PrintRejected,
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
            Self::A1NotReady => "A1 capsule must exist before Kit generation",
            Self::KitEncodingInvariant => "Kit encoding invariant failed",
            Self::PrintRejected => "Kit print page rejected",
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

/// Complete public artifacts from one deterministic v2 HOST provisioning run.
///
/// Every field is public wallet metadata. No transcript, entropy, mnemonic,
/// seed, scalar, chain code, xprv, Kit-R intermediate, setup payload, or pad
/// is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningArtifactsV2 {
    pub account_xpubs: [[u8; 111]; 2],
    pub descriptors: [[u8; 306]; 2],
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
    seed_a: Option<Secret<32>>,
    a2: Option<Secret<32>>,
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
            seed_a: Some(seed_a),
            a2: Some(a2),
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
        let seed_a = self
            .seed_a
            .as_ref()
            .ok_or(ProvisioningError::CryptographicInvariant)?;
        let a2 = self
            .a2
            .as_ref()
            .ok_or(ProvisioningError::CryptographicInvariant)?;
        let capsule = qk_a1::encrypt(
            a2.as_bytes(),
            &self.wallet.wallet_id,
            nonce,
            seed_a.as_bytes(),
        );
        drop(self.seed_a.take());
        drop(self.a2.take());
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

/// One v2 HOST provisioning run retaining the setup payload and Kit-R pad.
///
/// This type deliberately implements no `Clone`, `Copy`, `Debug`, display,
/// equality, serialization, logging, or secret-access trait. Its two private
/// fixed-size owners remain live across A1 construction for a later consuming
/// setup slice and are cleared on drop.
pub struct HostProvisioningRunV2 {
    payload: Secret<96>,
    // Retained intentionally for the later consuming setup slice; slice 4
    // permits no operation that reads or exposes this owner.
    #[allow(dead_code)]
    kit_r_pad: Secret<96>,
    account_xpubs: [[u8; 111]; 2],
    wallet: WalletPublicV2,
    nonce: Option<[u8; 12]>,
}

impl HostProvisioningRunV2 {
    fn from_secrets(secrets: [Secret<32>; 4]) -> Result<Self, ProvisioningError> {
        let [seed_a, signer_b, kit_r_transcript_hash, a2] = secrets;

        let seed_a_bip39 = bip39::entropy_to_seed(seed_a.as_bytes())?;
        let account_a = derive_account(seed_a_bip39.as_bytes())?;
        drop(seed_a_bip39);

        let signer_b_bip39 = bip39::entropy_to_seed(signer_b.as_bytes())?;
        let account_b = derive_account(signer_b_bip39.as_bytes())?;
        drop(signer_b_bip39);

        let account_xpubs = [account_a.xpub, account_b.xpub];
        let wallet = build_wallet_v2([account_a, account_b])?;
        let kit_r_pad = kit_r::derive_pad(&kit_r_transcript_hash, &wallet.wallet_id)?;
        #[cfg(any(test, feature = "fuzzing"))]
        kit_r::assert_reference(&kit_r_transcript_hash, &wallet.wallet_id, &kit_r_pad);
        drop(kit_r_transcript_hash);

        let mut payload = [0u8; 96];
        payload[..32].copy_from_slice(seed_a.as_bytes());
        payload[32..64].copy_from_slice(signer_b.as_bytes());
        payload[64..].copy_from_slice(a2.as_bytes());
        let payload = Secret::take(&mut payload);
        drop(seed_a);
        drop(signer_b);
        drop(a2);

        Ok(Self {
            payload,
            kit_r_pad,
            account_xpubs,
            wallet,
            nonce: None,
        })
    }

    /// Build one v2 run from four exact 100-symbol ManualKeypad transcripts.
    ///
    /// The fixed order is Seed-A, Signer-B, Kit-R, and A2. The existing M26
    /// literal-hash validator supplies count, symbol, and pairwise-reuse
    /// enforcement without a v2 QKEC or DiceGrid entry point.
    pub fn from_manual_dice(transcripts: [&[u8]; 4]) -> Result<Self, ProvisioningError> {
        Self::from_secrets(dice::digest_four(transcripts)?)
    }

    /// Encrypt Seed-A once and return only the complete public v2 artifact bundle.
    ///
    /// A repeated equal nonce is [`ProvisioningError::NonceReuse`]. A second
    /// attempt with any different nonce is [`ProvisioningError::AlreadyEncrypted`].
    /// The retained payload and pad are neither consumed nor exposed.
    pub fn encrypt_a1(
        &mut self,
        nonce: &[u8; 12],
    ) -> Result<ProvisioningArtifactsV2, ProvisioningError> {
        if let Some(previous) = self.nonce {
            return if previous == *nonce {
                Err(ProvisioningError::NonceReuse)
            } else {
                Err(ProvisioningError::AlreadyEncrypted)
            };
        }
        let seed_a: &[u8; 32] = self.payload.as_bytes()[..32]
            .try_into()
            .map_err(|_| ProvisioningError::CryptographicInvariant)?;
        let a2: &[u8; 32] = self.payload.as_bytes()[64..]
            .try_into()
            .map_err(|_| ProvisioningError::CryptographicInvariant)?;
        let capsule = qk_a1::encrypt(a2, &self.wallet.wallet_id, nonce, seed_a);
        self.nonce = Some(*nonce);
        Ok(ProvisioningArtifactsV2 {
            account_xpubs: self.account_xpubs,
            descriptors: self.wallet.descriptors,
            wallet_id: self.wallet.wallet_id,
            first_scripts: self.wallet.scripts,
            first_addresses: self.wallet.addresses,
            a1_capsule: capsule,
        })
    }
}

impl Drop for HostProvisioningRunV2 {
    fn drop(&mut self) {
        secret::wipe(self.payload.as_mut_bytes());
        secret::wipe(self.kit_r_pad.as_mut_bytes());
        #[cfg(any(test, feature = "fuzzing"))]
        {
            assert!(
                self.payload.as_bytes().iter().all(|&byte| byte == 0),
                "v2 payload wipe failed"
            );
            assert!(
                self.kit_r_pad.as_bytes().iter().all(|&byte| byte == 0),
                "Kit-R pad wipe failed"
            );
        }
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
mod v2_public_tests {
    use super::{HostProvisioningRunV2, ProvisioningError};

    #[test]
    fn v2_nonce_state_is_fail_closed_without_consuming_private_owners() {
        let transcripts = [[b'1'; 100], [b'2'; 100], [b'3'; 100], [b'4'; 100]];
        let refs = [
            &transcripts[0][..],
            &transcripts[1][..],
            &transcripts[2][..],
            &transcripts[3][..],
        ];
        let nonce = [0x42; 12];
        let other = [0x43; 12];
        let mut run =
            HostProvisioningRunV2::from_manual_dice(refs).expect("public deterministic v2 run");
        let artifacts = run.encrypt_a1(&nonce).expect("first encryption");
        assert_eq!(artifacts.account_xpubs.len(), 2);
        assert_eq!(artifacts.descriptors[0].len(), 306);
        assert_eq!(run.encrypt_a1(&nonce), Err(ProvisioningError::NonceReuse));
        assert_eq!(
            run.encrypt_a1(&other),
            Err(ProvisioningError::AlreadyEncrypted)
        );
        assert!(run.payload.as_bytes().iter().any(|&byte| byte != 0));
        assert!(run.kit_r_pad.as_bytes().iter().any(|&byte| byte != 0));
    }
}

#[cfg(test)]
mod fixture_tests;

#[cfg(test)]
mod fixture_tests_v2;
