//! Private adapter from the shared v2 wallet-mathematics boundary.

use crate::ProvisioningError;

pub(crate) struct WalletPublicV2 {
    pub(crate) descriptors: [[u8; 306]; 2],
    pub(crate) wallet_id: [u8; 32],
    pub(crate) scripts: [[u8; 34]; 2],
    pub(crate) addresses: [[u8; 62]; 2],
}

fn map_error(error: qk_wallet_v2::WalletV2Error) -> ProvisioningError {
    match error {
        qk_wallet_v2::WalletV2Error::InvalidMasterScalar => ProvisioningError::InvalidMasterScalar,
        qk_wallet_v2::WalletV2Error::InvalidChildTweak => ProvisioningError::InvalidChildTweak,
        qk_wallet_v2::WalletV2Error::ZeroChild => ProvisioningError::ZeroChild,
        qk_wallet_v2::WalletV2Error::CryptographicBackend => {
            ProvisioningError::CryptographicBackend
        }
        qk_wallet_v2::WalletV2Error::CryptographicInvariant => {
            ProvisioningError::CryptographicInvariant
        }
        qk_wallet_v2::WalletV2Error::GeneratedDescriptorInvalid
        | qk_wallet_v2::WalletV2Error::RecoveredWalletMismatch => {
            ProvisioningError::GeneratedDescriptorInvalid
        }
    }
}

pub(crate) fn build_wallet_v2(
    seed_a: &[u8; 32],
    signer_b: &[u8; 32],
) -> Result<([[u8; 111]; 2], WalletPublicV2), ProvisioningError> {
    let wallet = qk_wallet_v2::derive_wallet_v2(seed_a, signer_b).map_err(map_error)?;
    Ok((
        wallet.account_xpubs(),
        WalletPublicV2 {
            descriptors: wallet.descriptors(),
            wallet_id: wallet.wallet_id(),
            scripts: wallet.first_scripts(),
            addresses: wallet.first_addresses(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::build_wallet_v2;
    use crate::ProvisioningError;

    #[test]
    fn duplicate_generated_v2_accounts_are_a_named_descriptor_rejection() {
        let seed = [0x42u8; 32];
        assert!(matches!(
            build_wallet_v2(&seed, &seed),
            Err(ProvisioningError::GeneratedDescriptorInvalid)
        ));
    }
}
