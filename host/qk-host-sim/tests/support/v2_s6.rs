#![allow(dead_code)]

use qk_host_sim::{
    WatchOnlyCoordinatorTierV2, WatchOnlyExportArtifactsV2, WatchOnlyExportErrorV2,
    WatchOnlyExportNonceV2,
};
use qk_provisioning::ProvisioningArtifactsV2;

#[path = "../../../qk-psbt/src/sha256.rs"]
mod fixture_sha256;

pub const FIXTURE: &[u8] = include_bytes!("../fixtures/watch_only_v2.txt");
pub const FIXTURE_BYTES: usize = 5_803;
pub const FIXTURE_LF: usize = 43;
pub const FIXTURE_SHA256: &str = "592a12af3d13ba5a3e76178cc272a2a22be62cd80bc997126574aee2f16af8a7";

pub fn field(name: &str) -> &'static str {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = core::str::from_utf8(line).expect("v2 slice-6 fixture ASCII");
            line.strip_prefix(&format!("{name}: "))
        })
        .expect("v2 slice-6 fixture field")
}

pub fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex width");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

pub fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex(value).try_into().expect("exact fixture field width")
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = fixture_sha256::Sha256::new();
    hasher.update(bytes).expect("fixture hash update");
    hasher.finalize().expect("fixture hash finalization")
}

pub fn provisioning() -> ProvisioningArtifactsV2 {
    let receive: [u8; 306] = field("receive_descriptor")
        .as_bytes()
        .try_into()
        .expect("receive descriptor width");
    let change: [u8; 306] = field("change_descriptor")
        .as_bytes()
        .try_into()
        .expect("change descriptor width");
    let mut account_xpubs = [[0u8; 111]; 2];
    for (slot, start) in account_xpubs.iter_mut().zip([41usize, 180]) {
        slot.copy_from_slice(&receive[start..start + 111]);
    }
    ProvisioningArtifactsV2 {
        account_xpubs,
        descriptors: [receive, change],
        wallet_id: hex_array(field("wallet_id")),
        first_scripts: [
            hex_array(field("receive_0_script_pubkey")),
            hex_array(field("change_0_script_pubkey")),
        ],
        first_addresses: [
            field("receive_0_address")
                .as_bytes()
                .try_into()
                .expect("receive address width"),
            field("change_0_address")
                .as_bytes()
                .try_into()
                .expect("change address width"),
        ],
        a1_capsule: [0u8; 67],
    }
}

pub fn owner(
    tier: WatchOnlyCoordinatorTierV2,
) -> Result<WatchOnlyExportArtifactsV2, WatchOnlyExportErrorV2> {
    WatchOnlyExportArtifactsV2::from_provisioning(&provisioning(), tier)
}

pub fn nonce() -> WatchOnlyExportNonceV2 {
    WatchOnlyExportNonceV2::from_bytes(hex_array(field("caller_nonce_hex")))
}

pub fn bsms_bytes() -> Vec<u8> {
    hex(field("bsms_bytes_hex"))
}
