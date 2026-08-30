//! Exact recovered-wallet bind tests for the Kit-Spend boundary.

use qk_kit::{combine_frames, KitSpendMathErrorV3};

const PROVISIONING: &[u8] =
    include_bytes!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &[u8] = include_bytes!("fixtures/kit_share_v2.txt");

fn fixture_text(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).expect("registered ASCII fixture")
}

fn field<'a>(fixture: &'a [u8], name: &str) -> &'a str {
    fixture_text(fixture)
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

fn recovered() -> qk_kit::RecoveredKitPayload {
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
fn exact_recovered_wallet_binds_before_any_sweep_exists() {
    let bound = recovered()
        .bind_spend_v2(&descriptors(), &wallet_id())
        .expect("registered recovered wallet");
    assert_eq!(bound.wallet_id(), wallet_id());
    drop(bound);
}

#[test]
fn every_descriptor_or_wallet_identity_difference_has_one_closed_rejection() {
    let mut wrong_descriptors = descriptors();
    wrong_descriptors[0][0] ^= 1;
    assert!(matches!(
        recovered().bind_spend_v2(&wrong_descriptors, &wallet_id()),
        Err(KitSpendMathErrorV3::RecoveredWalletMismatch)
    ));

    let mut wrong_wallet = wallet_id();
    wrong_wallet[31] ^= 1;
    assert!(matches!(
        recovered().bind_spend_v2(&descriptors(), &wrong_wallet),
        Err(KitSpendMathErrorV3::RecoveredWalletMismatch)
    ));
}

#[test]
fn math_errors_are_fixed_named_categories() {
    let cases = [
        (
            KitSpendMathErrorV3::RecoveredWalletMismatch,
            "RecoveredWalletMismatch",
        ),
        (
            KitSpendMathErrorV3::ValidatedWalletMismatch,
            "ValidatedWalletMismatch",
        ),
        (
            KitSpendMathErrorV3::InvalidSigningPlan,
            "InvalidSigningPlan",
        ),
        (
            KitSpendMathErrorV3::ChildDerivationFailed,
            "ChildDerivationFailed",
        ),
        (
            KitSpendMathErrorV3::ExpectedPublicKeyMismatch,
            "ExpectedPublicKeyMismatch",
        ),
        (
            KitSpendMathErrorV3::CryptographicSigningFailed,
            "CryptographicSigningFailed",
        ),
        (
            KitSpendMathErrorV3::DuplicateSignature,
            "DuplicateSignature",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.name(), expected);
        assert_eq!(error.to_string(), expected);
    }
}
