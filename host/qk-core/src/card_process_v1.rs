//! HOST-only binding between the byte-complete Key Card B protocol and the
//! existing typed qk-core card owner.
//!
//! This module performs no I/O and owns no signing operation. Card responses
//! reach it only after the protocol crate has parsed their hostile bytes.

use crate::capability::{NormalCardBDataV2, NormalCardMockErrorV2};
use crate::normal_artifact_v2::NormalProfileV2;
use crate::wipe;
use core::fmt;
use qk_bip32::decode_mainnet_xpub;
use qk_card_protocol::{
    parse_record, Lifecycle, Mode, Profile, ResponseRef, DESCRIPTOR_BYTES, RAW_XPUB_BYTES,
    RECORD_VERSION, ROLE_KEY_CARD_B,
};
use qk_descriptor::parse_descriptor_pair_v2;

const ROLE_B_XPUB_START: usize = 180;
const ROLE_B_XPUB_END: usize = 291;
const MAINNET_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

const _: () = assert!(ROLE_B_XPUB_END - ROLE_B_XPUB_START == 111);
const _: () = assert!(ROLE_B_XPUB_END <= DESCRIPTOR_BYTES);

/// Closed binding failures after hostile response parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardProcessErrorV1 {
    UnexpectedResponse,
    RecordRejected,
    InfoRecordVersionMismatch,
    InfoLifecycleMismatch,
    InfoProfileMismatch,
    InfoRoleMismatch,
    InfoOperationMaskMismatch,
    DescriptorRejected,
    DescriptorByteMismatch,
    WalletBindingMismatch,
    OriginFingerprintMismatch,
    AccountXpubMismatch,
    CardDataRejected,
}

impl CardProcessErrorV1 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnexpectedResponse => "CardUnexpectedResponse",
            Self::RecordRejected => "CardRecordRejected",
            Self::InfoRecordVersionMismatch => "CardInfoRecordVersionMismatch",
            Self::InfoLifecycleMismatch => "CardInfoLifecycleMismatch",
            Self::InfoProfileMismatch => "CardInfoProfileMismatch",
            Self::InfoRoleMismatch => "CardInfoRoleMismatch",
            Self::InfoOperationMaskMismatch => "CardInfoOperationMaskMismatch",
            Self::DescriptorRejected => "CardDescriptorRejected",
            Self::DescriptorByteMismatch => "CardDescriptorByteMismatch",
            Self::WalletBindingMismatch => "CardWalletBindingMismatch",
            Self::OriginFingerprintMismatch => "CardOriginFingerprintMismatch",
            Self::AccountXpubMismatch => "CardAccountXpubMismatch",
            Self::CardDataRejected => "CardDataRejected",
        }
    }
}

impl fmt::Display for CardProcessErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for CardProcessErrorV1 {}

/// Owned public GET_INFO facts. No record, A2, scalar or signature is present.
#[derive(Eq, PartialEq)]
pub struct CardInfoV1 {
    record_version: u8,
    lifecycle: u8,
    profile: u8,
    role: u8,
    instance_id: [u8; 16],
    wallet_id: [u8; 32],
    origin_fingerprint: [u8; 4],
    account_xpub: [u8; RAW_XPUB_BYTES],
    allowed_operations: u16,
}

impl CardInfoV1 {
    /// Copy only a protocol-validated GET_INFO success response.
    pub fn try_from_response(response: ResponseRef<'_>) -> Result<Self, CardProcessErrorV1> {
        let ResponseRef::GetInfo {
            record_version,
            lifecycle,
            profile,
            role,
            instance_id,
            wallet_id,
            origin_fingerprint,
            account_xpub,
            allowed_operations,
            ..
        } = response
        else {
            return Err(CardProcessErrorV1::UnexpectedResponse);
        };
        Ok(Self {
            record_version,
            lifecycle,
            profile,
            role,
            instance_id: *instance_id,
            wallet_id: *wallet_id,
            origin_fingerprint: *origin_fingerprint,
            account_xpub: *account_xpub,
            allowed_operations,
        })
    }

    pub const fn profile(&self) -> u8 {
        self.profile
    }

    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn account_xpub(&self) -> [u8; RAW_XPUB_BYTES] {
        self.account_xpub
    }
}

/// Bind a complete Normal card read to the selected owner-side profile and
/// construct the existing move-only qk-core card factor with no preloaded
/// signatures. The mutable A2 source is cleared on every return path.
pub fn bind_normal_card_v1(
    selected_profile: NormalProfileV2,
    info: CardInfoV1,
    descriptors: [[u8; DESCRIPTOR_BYTES]; 2],
    a2: &mut [u8; 32],
) -> Result<NormalCardBDataV2, CardProcessErrorV1> {
    let result = validate_normal_info_v1(selected_profile, &info)
        .and_then(|()| validate_normal_descriptors_v1(&info, &descriptors));
    if let Err(error) = result {
        wipe::bytes(a2);
        return Err(error);
    }
    let mut account_xpub = [0u8; 111];
    account_xpub.copy_from_slice(&descriptors[0][ROLE_B_XPUB_START..ROLE_B_XPUB_END]);
    NormalCardBDataV2::try_new(descriptors, info.wallet_id, account_xpub, a2, Vec::new())
        .map_err(map_card_data_error)
}

/// Reject a GET_INFO record that cannot be used for the selected Normal
/// profile. The runtime applies this gate before requesting either descriptor
/// or A2 from the card.
pub(crate) fn validate_normal_info_v1(
    selected_profile: NormalProfileV2,
    info: &CardInfoV1,
) -> Result<(), CardProcessErrorV1> {
    validate_info(
        info,
        expected_profile(selected_profile),
        Lifecycle::Committed,
        0x000f,
    )
}

/// Bind the two byte-exact descriptors, wallet identity, origin fingerprint,
/// and role-B account xpub before the runtime requests A2.
pub(crate) fn validate_normal_descriptors_v1(
    info: &CardInfoV1,
    descriptors: &[[u8; DESCRIPTOR_BYTES]; 2],
) -> Result<(), CardProcessErrorV1> {
    validate_descriptor_binding(info, descriptors)
}

/// Verify the post-COMMIT reselect/reopen/read-back facts against the exact
/// staged record. This function never derives an xpub from the private record;
/// it binds the returned public xpub to the byte-identical registered D pair.
pub fn verify_provisioned_card_v1(
    mode: Mode,
    record: &[u8],
    info: CardInfoV1,
    descriptors: &[[u8; DESCRIPTOR_BYTES]; 2],
) -> Result<(), CardProcessErrorV1> {
    let record = parse_record(record).map_err(|_| CardProcessErrorV1::RecordRejected)?;
    if record.receive_descriptor() != &descriptors[0]
        || record.change_descriptor() != &descriptors[1]
    {
        return Err(CardProcessErrorV1::DescriptorByteMismatch);
    }
    let expected_operations = match mode {
        Mode::Setup => 0x0007,
        Mode::KitRestore => 0x0003,
        Mode::Normal | Mode::Rescue => return Err(CardProcessErrorV1::InfoLifecycleMismatch),
    };
    validate_info(
        &info,
        record.profile(),
        Lifecycle::Committed,
        expected_operations,
    )?;
    if info.instance_id != *record.instance_id() || info.wallet_id != *record.wallet_id() {
        return Err(CardProcessErrorV1::WalletBindingMismatch);
    }
    if info.origin_fingerprint != *record.origin_fingerprint() {
        return Err(CardProcessErrorV1::OriginFingerprintMismatch);
    }
    validate_descriptor_binding(&info, descriptors)
}

fn validate_info(
    info: &CardInfoV1,
    expected_profile: Profile,
    expected_lifecycle: Lifecycle,
    expected_operations: u16,
) -> Result<(), CardProcessErrorV1> {
    if info.record_version != RECORD_VERSION {
        return Err(CardProcessErrorV1::InfoRecordVersionMismatch);
    }
    if info.lifecycle != expected_lifecycle.byte() {
        return Err(CardProcessErrorV1::InfoLifecycleMismatch);
    }
    if info.profile != expected_profile.byte() {
        return Err(CardProcessErrorV1::InfoProfileMismatch);
    }
    if info.role != ROLE_KEY_CARD_B {
        return Err(CardProcessErrorV1::InfoRoleMismatch);
    }
    if info.allowed_operations != expected_operations {
        return Err(CardProcessErrorV1::InfoOperationMaskMismatch);
    }
    Ok(())
}

fn validate_descriptor_binding(
    info: &CardInfoV1,
    descriptors: &[[u8; DESCRIPTOR_BYTES]; 2],
) -> Result<(), CardProcessErrorV1> {
    let pair = parse_descriptor_pair_v2(&descriptors[0], &descriptors[1])
        .map_err(|_| CardProcessErrorV1::DescriptorRejected)?;
    if pair.wallet_id() != info.wallet_id {
        return Err(CardProcessErrorV1::WalletBindingMismatch);
    }
    if pair.origin_fingerprints()[1] != info.origin_fingerprint {
        return Err(CardProcessErrorV1::OriginFingerprintMismatch);
    }
    for descriptor in descriptors {
        let xpub = descriptor
            .get(ROLE_B_XPUB_START..ROLE_B_XPUB_END)
            .ok_or(CardProcessErrorV1::DescriptorRejected)?;
        if !raw_xpub_matches_text(&info.account_xpub, xpub) {
            return Err(CardProcessErrorV1::AccountXpubMismatch);
        }
    }
    Ok(())
}

fn raw_xpub_matches_text(raw: &[u8; RAW_XPUB_BYTES], text: &[u8]) -> bool {
    let Ok(decoded) = decode_mainnet_xpub(text) else {
        return false;
    };
    raw[0..4] == MAINNET_XPUB_VERSION
        && raw[4] == decoded.public_node.depth
        && raw[5..9] == decoded.parent_fingerprint
        && raw[9..13] == decoded.child_number.to_be_bytes()
        && raw[13..45] == decoded.public_node.chain_code
        && raw[45..78] == decoded.public_node.compressed_public_key
}

const fn expected_profile(profile: NormalProfileV2) -> Profile {
    match profile {
        NormalProfileV2::SimpleRecovery => Profile::SimpleRecovery,
        NormalProfileV2::Inheritance => Profile::Inheritance,
        NormalProfileV2::QuantumShelter => Profile::QuantumShelter,
    }
}

fn map_card_data_error(_: NormalCardMockErrorV2) -> CardProcessErrorV1 {
    CardProcessErrorV1::CardDataRejected
}

#[cfg(test)]
mod tests {
    use super::{validate_normal_info_v1, CardInfoV1, CardProcessErrorV1};
    use crate::NormalProfileV2;
    use qk_card_protocol::{Lifecycle, Profile, RAW_XPUB_BYTES, RECORD_VERSION, ROLE_KEY_CARD_B};

    fn committed_info() -> CardInfoV1 {
        CardInfoV1 {
            record_version: RECORD_VERSION,
            lifecycle: Lifecycle::Committed.byte(),
            profile: Profile::SimpleRecovery.byte(),
            role: ROLE_KEY_CARD_B,
            instance_id: [0x11; 16],
            wallet_id: [0x22; 32],
            origin_fingerprint: [0x33; 4],
            account_xpub: [0x44; RAW_XPUB_BYTES],
            allowed_operations: 0x000f,
        }
    }

    #[test]
    fn normal_info_gate_precedes_descriptor_and_a2_access() {
        let mut info = committed_info();
        assert_eq!(
            validate_normal_info_v1(NormalProfileV2::SimpleRecovery, &info),
            Ok(())
        );

        info.lifecycle = Lifecycle::Staging.byte();
        assert_eq!(
            validate_normal_info_v1(NormalProfileV2::SimpleRecovery, &info),
            Err(CardProcessErrorV1::InfoLifecycleMismatch)
        );
        info = committed_info();
        info.profile = Profile::Inheritance.byte();
        assert_eq!(
            validate_normal_info_v1(NormalProfileV2::SimpleRecovery, &info),
            Err(CardProcessErrorV1::InfoProfileMismatch)
        );
        info = committed_info();
        info.role = 1;
        assert_eq!(
            validate_normal_info_v1(NormalProfileV2::SimpleRecovery, &info),
            Err(CardProcessErrorV1::InfoRoleMismatch)
        );
        info = committed_info();
        info.allowed_operations = 0x0007;
        assert_eq!(
            validate_normal_info_v1(NormalProfileV2::SimpleRecovery, &info),
            Err(CardProcessErrorV1::InfoOperationMaskMismatch)
        );
    }
}
