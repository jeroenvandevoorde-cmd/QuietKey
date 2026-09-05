//! Byte-exact card-protocol binding to the registered public fixture.
//!
//! PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL. The fixture is the sole
//! authority and records both outside-Git constructors and their agreement.

#![cfg(feature = "normal-process")]

use std::collections::BTreeMap;

use qk_card_protocol::{parse_response, Instruction, Mode, ResponseRef, DESCRIPTOR_BYTES};
use qk_core::{
    bind_normal_card_v1, verify_provisioned_card_v1, CardInfoV1, CardProcessErrorV1,
    NormalProfileV2,
};

const FIXTURE: &str = include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

fn fixture() -> BTreeMap<&'static str, &'static str> {
    let fields: BTreeMap<_, _> = FIXTURE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once(": ").expect("fixture field"))
        .collect();
    assert_eq!(fields.len(), 81);
    fields
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("fixture hex")
        })
        .collect()
}

fn bytes(fields: &BTreeMap<&str, &str>, name: &str) -> Vec<u8> {
    decode_hex(fields.get(name).expect("fixture field"))
}

fn descriptors(fields: &BTreeMap<&str, &str>) -> [[u8; DESCRIPTOR_BYTES]; 2] {
    [
        fields["receive_descriptor"]
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        fields["change_descriptor"]
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ]
}

fn info_from_response(mut response: Vec<u8>, profile: u8, operation_mask: u16) -> CardInfoV1 {
    assert_eq!(response.len(), 160);
    response[24] = profile;
    response[156..158].copy_from_slice(&operation_mask.to_be_bytes());
    let parsed = parse_response(Instruction::GetInfo, &response).expect("typed INFO");
    CardInfoV1::try_from_response(parsed).expect("owned INFO")
}

#[test]
fn every_profile_binds_the_registered_info_descriptors_xpub_and_wallet() {
    let fields = fixture();
    let response = bytes(&fields, "normal_info_response_hex");
    let descriptors = descriptors(&fields);
    let expected_wallet = bytes(&fields, "wallet_id_hex");
    let expected_xpub = fields["account_xpub_text"].as_bytes();
    for (profile, byte) in [
        (NormalProfileV2::SimpleRecovery, 1u8),
        (NormalProfileV2::Inheritance, 2),
        (NormalProfileV2::QuantumShelter, 3),
    ] {
        let info = info_from_response(response.clone(), byte, 0x000f);
        let mut a2: [u8; 32] = bytes(&fields, "a2_hex").try_into().expect("A2 width");
        let bound = bind_normal_card_v1(profile, info, descriptors, &mut a2).expect("bound card");
        assert!(a2.iter().all(|byte| *byte == 0));
        assert_eq!(bound.wallet_id().as_slice(), expected_wallet);
        assert_eq!(bound.account_xpub().as_slice(), expected_xpub);
        assert_eq!(bound.descriptors(), &descriptors);
        assert!(bound.signatures().is_empty());
    }
}

#[test]
fn post_commit_readback_requires_exact_staged_record_and_setup_mask() {
    let fields = fixture();
    let response = bytes(&fields, "normal_info_response_hex");
    let descriptors = descriptors(&fields);
    let record = bytes(&fields, "record_profile_01_hex");
    let info = info_from_response(response.clone(), 1, 0x0007);
    assert_eq!(
        verify_provisioned_card_v1(Mode::Setup, &record, info, &descriptors),
        Ok(())
    );

    let mut changed = descriptors;
    changed[0][0] ^= 1;
    let info = info_from_response(response.clone(), 1, 0x0007);
    assert_eq!(
        verify_provisioned_card_v1(Mode::Setup, &record, info, &changed),
        Err(CardProcessErrorV1::DescriptorByteMismatch)
    );

    let info = info_from_response(response, 1, 0x000f);
    assert_eq!(
        verify_provisioned_card_v1(Mode::Setup, &record, info, &descriptors),
        Err(CardProcessErrorV1::InfoOperationMaskMismatch)
    );
}

#[test]
fn wrong_profile_rejects_and_clears_a2_before_any_factor_exists() {
    let fields = fixture();
    let response = bytes(&fields, "normal_info_response_hex");
    let info = info_from_response(response, 2, 0x000f);
    let mut a2: [u8; 32] = bytes(&fields, "a2_hex").try_into().expect("A2 width");
    assert_eq!(
        bind_normal_card_v1(
            NormalProfileV2::SimpleRecovery,
            info,
            descriptors(&fields),
            &mut a2,
        )
        .map(|_| ()),
        Err(CardProcessErrorV1::InfoProfileMismatch)
    );
    assert!(a2.iter().all(|byte| *byte == 0));
}

#[test]
fn info_wallet_mutation_has_exact_named_rejection() {
    let fields = fixture();
    let descriptors = descriptors(&fields);

    let mut wrong_wallet = bytes(&fields, "normal_info_response_hex");
    wrong_wallet[42] ^= 1;
    let info = info_from_response(wrong_wallet, 1, 0x000f);
    let mut a2: [u8; 32] = bytes(&fields, "a2_hex").try_into().expect("A2 width");
    assert_eq!(
        bind_normal_card_v1(NormalProfileV2::SimpleRecovery, info, descriptors, &mut a2,)
            .map(|_| ()),
        Err(CardProcessErrorV1::WalletBindingMismatch)
    );
    assert!(a2.iter().all(|byte| *byte == 0));
}

#[test]
fn every_binding_error_name_is_stable() {
    for (error, name) in [
        (
            CardProcessErrorV1::UnexpectedResponse,
            "CardUnexpectedResponse",
        ),
        (CardProcessErrorV1::RecordRejected, "CardRecordRejected"),
        (
            CardProcessErrorV1::InfoRecordVersionMismatch,
            "CardInfoRecordVersionMismatch",
        ),
        (
            CardProcessErrorV1::InfoLifecycleMismatch,
            "CardInfoLifecycleMismatch",
        ),
        (
            CardProcessErrorV1::InfoProfileMismatch,
            "CardInfoProfileMismatch",
        ),
        (CardProcessErrorV1::InfoRoleMismatch, "CardInfoRoleMismatch"),
        (
            CardProcessErrorV1::InfoOperationMaskMismatch,
            "CardInfoOperationMaskMismatch",
        ),
        (
            CardProcessErrorV1::DescriptorRejected,
            "CardDescriptorRejected",
        ),
        (
            CardProcessErrorV1::DescriptorByteMismatch,
            "CardDescriptorByteMismatch",
        ),
        (
            CardProcessErrorV1::WalletBindingMismatch,
            "CardWalletBindingMismatch",
        ),
        (
            CardProcessErrorV1::OriginFingerprintMismatch,
            "CardOriginFingerprintMismatch",
        ),
        (
            CardProcessErrorV1::AccountXpubMismatch,
            "CardAccountXpubMismatch",
        ),
        (CardProcessErrorV1::CardDataRejected, "CardDataRejected"),
    ] {
        assert_eq!(error.name(), name);
        assert_eq!(error.to_string(), name);
    }
    let rejected = parse_response(Instruction::GetInfo, &[0x6f, 0x03]).expect("rejection");
    assert!(matches!(rejected, ResponseRef::Rejected(_)));
    assert!(matches!(
        CardInfoV1::try_from_response(rejected),
        Err(CardProcessErrorV1::UnexpectedResponse)
    ));
}
