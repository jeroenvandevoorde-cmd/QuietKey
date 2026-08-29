//! V2 slice-6 public-surface and transport fences.

#[path = "support/v2_s6.rs"]
mod support;

use qk_host_sim::{
    BsmsErrorV2, WatchOnlyArtifactMetadataV2, WatchOnlyBsmsArtifactV2, WatchOnlyCoordinatorTierV2,
    WatchOnlyExportArtifactsV2, WatchOnlyExportErrorV2, WatchOnlyExportNonceV2,
    WatchOnlyMockFileKindV2, WatchOnlyMockSdFilesystemV2, WatchOnlySdArtifactNamesV2,
    WatchOnlySdExportErrorV2, WatchOnlySdExportFaultV2, WatchOnlySdFileNameV2,
    WatchOnlySdLifecycleEventV2, WatchOnlySdPublishedArtifactV2, BSMS_RECORD_BYTES_V2,
};
use support::{bsms_bytes, field, hex_array, nonce, owner, sha256};

const LIB: &str = include_str!("../src/lib.rs");
const BSMS_V1: &str = include_str!("../src/bsms.rs");
const WATCH_ONLY_V1: &str = include_str!("../src/watch_only_export.rs");
const BSMS_V2: &str = include_str!("../src/bsms_v2.rs");
const WATCH_ONLY_V2: &str = include_str!("../src/watch_only_export_v2.rs");

#[test]
fn public_surface_is_the_closed_v2_bsms_artifact_and_mock_sd_boundary() {
    let public_lines: Vec<&str> = WATCH_ONLY_V2
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub type WatchOnlySdExportErrorV2 = SdExportError;",
            "pub type WatchOnlySdExportFaultV2 = SdExportFault;",
            "pub enum WatchOnlyCoordinatorTierV2 {",
            "pub enum WatchOnlyExportErrorV2 {",
            "pub struct WatchOnlyArtifactMetadataV2 {",
            "pub const fn serialized_len(&self) -> usize {",
            "pub const fn sha256(&self) -> [u8; 32] {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn first_addresses(&self) -> [[u8; 62]; 2] {",
            "pub const fn first_receive_address(&self) -> [u8; 62] {",
            "pub const fn first_change_address(&self) -> [u8; 62] {",
            "pub struct WatchOnlyExportNonceV2([u8; NONCE_BYTES]);",
            "pub const fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {",
            "pub struct WatchOnlySdFileNameV2(String);",
            "pub fn as_str(&self) -> &str {",
            "pub struct WatchOnlySdArtifactNamesV2 {",
            "pub fn final_name(&self) -> &WatchOnlySdFileNameV2 {",
            "pub fn temporary_name(&self) -> &WatchOnlySdFileNameV2 {",
            "pub struct WatchOnlyExportArtifactsV2 {",
            "pub fn from_provisioning(",
            "pub const fn tier(&self) -> WatchOnlyCoordinatorTierV2 {",
            "pub const fn artifact(&self) -> WatchOnlyBsmsArtifactV2<'_> {",
            "pub struct WatchOnlyBsmsArtifactV2<'a> {",
            "pub const fn bytes(&self) -> &'a [u8; BSMS_RECORD_BYTES_V2] {",
            "pub const fn metadata(&self) -> WatchOnlyArtifactMetadataV2 {",
            "pub fn verify_reopened(&self, reopened: &[u8]) -> Result<(), BsmsErrorV2> {",
            "pub fn write_mock_sd(",
            "pub struct WatchOnlySdPublishedArtifactV2 {",
            "pub const fn metadata(&self) -> WatchOnlyArtifactMetadataV2 {",
            "pub fn names(&self) -> &WatchOnlySdArtifactNamesV2 {",
            "pub enum WatchOnlyMockFileKindV2 {",
            "pub enum WatchOnlySdLifecycleEventV2 {",
            "pub struct WatchOnlyMockSdFilesystemV2 {",
            "pub fn new() -> Self {",
            "pub fn insert_existing(&mut self, name: &str, bytes: &[u8]) -> bool {",
            "pub fn file_bytes(&self, name: &WatchOnlySdFileNameV2) -> Option<&[u8]> {",
            "pub fn existing_file_bytes(&self, name: &str) -> Option<&[u8]> {",
            "pub fn file_kind(&self, name: &WatchOnlySdFileNameV2) -> Option<WatchOnlyMockFileKindV2> {",
            "pub fn events(&self) -> &[WatchOnlySdLifecycleEventV2] {",
        ],
        "complete v2 slice-6 public item and method surface"
    );

    assert!(LIB.contains("mod bsms_v2;"));
    assert!(LIB.contains("mod watch_only_export_v2;"));
    assert!(!LIB.contains("pub mod bsms_v2;"));
    assert!(!LIB.contains("pub mod watch_only_export_v2;"));
    assert!(LIB.contains("pub use bsms_v2::{BsmsErrorV2, BSMS_RECORD_BYTES_V2};"));
    assert!(!LIB.contains("pub use bsms_v2::{BsmsErrorV2, BsmsRecordV2"));

    let _: Option<WatchOnlyArtifactMetadataV2> = None;
    let _: Option<WatchOnlyBsmsArtifactV2<'_>> = None;
    let _: Option<WatchOnlyCoordinatorTierV2> = None;
    let _: Option<WatchOnlyExportArtifactsV2> = None;
    let _: Option<WatchOnlyExportNonceV2> = None;
    let _: Option<WatchOnlyMockFileKindV2> = None;
    let _: Option<WatchOnlyMockSdFilesystemV2> = None;
    let _: Option<WatchOnlySdArtifactNamesV2> = None;
    let _: Option<WatchOnlySdFileNameV2> = None;
    let _: Option<WatchOnlySdLifecycleEventV2> = None;
    let _: Option<WatchOnlySdPublishedArtifactV2> = None;
}

#[test]
fn served_tiers_expose_exact_bound_facts_and_quantum_rejects() {
    let expected = bsms_bytes();
    let expected_addresses = [
        *field("receive_0_address")
            .as_bytes()
            .first_chunk::<62>()
            .expect("receive address width"),
        *field("change_0_address")
            .as_bytes()
            .first_chunk::<62>()
            .expect("change address width"),
    ];

    for tier in [
        WatchOnlyCoordinatorTierV2::SimpleRecovery,
        WatchOnlyCoordinatorTierV2::Inheritance,
    ] {
        let artifacts = owner(tier).expect("served v2 coordinator tier");
        assert_eq!(artifacts.tier(), tier);
        let artifact = artifacts.artifact();
        assert_eq!(artifact.bytes().as_slice(), expected);
        let metadata = artifact.metadata();
        assert_eq!(metadata.serialized_len(), BSMS_RECORD_BYTES_V2);
        assert_eq!(metadata.sha256(), sha256(&expected));
        assert_eq!(metadata.wallet_id(), hex_array(field("wallet_id")));
        assert_eq!(metadata.first_addresses(), expected_addresses);
        assert_eq!(metadata.first_receive_address(), expected_addresses[0]);
        assert_eq!(metadata.first_change_address(), expected_addresses[1]);

        let mut filesystem = WatchOnlyMockSdFilesystemV2::new();
        let published = artifact
            .write_mock_sd(nonce(), &mut filesystem, None)
            .expect("served v2 SD publication");
        assert_eq!(published.metadata(), metadata);
        assert_eq!(published.names().final_name().as_str(), field("final_name"));
        assert_eq!(
            filesystem.file_kind(published.names().final_name()),
            Some(WatchOnlyMockFileKindV2::Final)
        );
        assert_eq!(
            filesystem.file_bytes(published.names().final_name()),
            Some(expected.as_slice())
        );
    }

    assert!(matches!(
        owner(WatchOnlyCoordinatorTierV2::QuantumShelter),
        Err(WatchOnlyExportErrorV2::QuantumShelterDescriptorExport)
    ));
}

#[test]
fn every_closed_error_has_exact_stable_display_text() {
    assert_error::<BsmsErrorV2>();
    assert_error::<WatchOnlyExportErrorV2>();
    assert_error::<WatchOnlySdExportErrorV2>();

    for error in [
        BsmsErrorV2::InvalidDescriptorPair,
        BsmsErrorV2::WalletIdMismatch,
        BsmsErrorV2::FirstScriptMismatch,
        BsmsErrorV2::FirstAddressMismatch,
        BsmsErrorV2::DescriptorRoundTripMismatch,
        BsmsErrorV2::InvalidRecordLength,
        BsmsErrorV2::InvalidRecordEncoding,
        BsmsErrorV2::InvalidVersionLine,
        BsmsErrorV2::InvalidDescriptorLine,
        BsmsErrorV2::InvalidRestrictionsLine,
        BsmsErrorV2::InvalidAddressLine,
    ] {
        assert_eq!(error.to_string(), expected_bsms_display(error));
        assert_eq!(
            WatchOnlyExportErrorV2::Bsms(error).to_string(),
            expected_bsms_display(error)
        );
    }
    assert_eq!(
        WatchOnlyExportErrorV2::QuantumShelterDescriptorExport.to_string(),
        "QuantumShelterDescriptorExport"
    );
    assert_eq!(
        WatchOnlyExportErrorV2::HashingInvariant.to_string(),
        "watch-only artifact hashing invariant"
    );

    for error in [
        WatchOnlySdExportErrorV2::FullMedia,
        WatchOnlySdExportErrorV2::TemporaryCreateFailed,
        WatchOnlySdExportErrorV2::WriteFailed,
        WatchOnlySdExportErrorV2::SyncFailed,
        WatchOnlySdExportErrorV2::CloseFailed,
        WatchOnlySdExportErrorV2::ReopenFailed,
        WatchOnlySdExportErrorV2::VerificationMismatch,
        WatchOnlySdExportErrorV2::FilenameCollision,
        WatchOnlySdExportErrorV2::RenameFailed,
    ] {
        assert_eq!(error.to_string(), expected_sd_display(error));
    }

    for fault in [
        WatchOnlySdExportFaultV2::FullMedia,
        WatchOnlySdExportFaultV2::TemporaryCreateFailed,
        WatchOnlySdExportFaultV2::WriteFailed,
        WatchOnlySdExportFaultV2::SyncFailed,
        WatchOnlySdExportFaultV2::CloseFailed,
        WatchOnlySdExportFaultV2::ReopenFailed,
        WatchOnlySdExportFaultV2::VerificationMismatch,
        WatchOnlySdExportFaultV2::RenameFailed,
    ] {
        assert!(!format!("{fault:?}").is_empty());
    }
}

#[test]
fn v2_descriptor_export_has_no_qr_real_io_or_secret_surface_and_v1_stays_separate() {
    let artifact_impl = WATCH_ONLY_V2
        .split_once("impl<'a> WatchOnlyBsmsArtifactV2<'a> {")
        .expect("v2 artifact implementation")
        .1
        .split_once("\n}\n\n/// Metadata and names")
        .expect("v2 artifact implementation boundary")
        .0;
    for forbidden in [
        "pub fn bbqr(",
        "pub fn qr(",
        "pub fn frames(",
        "pub fn encode_frame(",
    ] {
        assert!(
            !artifact_impl.contains(forbidden),
            "forbidden path {forbidden}"
        );
    }
    for forbidden in [
        "qk_bbqr",
        "SequentialPsbtBbqr",
        "encode_frame(",
        "std::fs",
        "OpenOptions",
        "File::",
        "std::net",
        "getrandom",
        "rand::",
        "private_key",
        "signing_key",
        "mnemonic",
        "xprv",
    ] {
        assert!(
            !WATCH_ONLY_V2.contains(forbidden),
            "scope fence {forbidden}"
        );
        assert!(!BSMS_V2.contains(forbidden), "BSMS fence {forbidden}");
    }

    assert!(BSMS_V1.contains("const ACCOUNT_COUNT: usize = 3;"));
    assert!(WATCH_ONLY_V1.contains("tier: KitTier"));
    assert!(!BSMS_V1.contains("BsmsErrorV2"));
    assert!(!WATCH_ONLY_V1.contains("WatchOnlyCoordinatorTierV2"));
}

fn assert_error<E: std::error::Error>() {}

fn expected_bsms_display(error: BsmsErrorV2) -> &'static str {
    match error {
        BsmsErrorV2::InvalidDescriptorPair => "InvalidDescriptorPair",
        BsmsErrorV2::WalletIdMismatch => "WalletIdMismatch",
        BsmsErrorV2::FirstScriptMismatch => "FirstScriptMismatch",
        BsmsErrorV2::FirstAddressMismatch => "FirstAddressMismatch",
        BsmsErrorV2::DescriptorRoundTripMismatch => "DescriptorRoundTripMismatch",
        BsmsErrorV2::InvalidRecordLength => "InvalidRecordLength",
        BsmsErrorV2::InvalidRecordEncoding => "InvalidRecordEncoding",
        BsmsErrorV2::InvalidVersionLine => "InvalidVersionLine",
        BsmsErrorV2::InvalidDescriptorLine => "InvalidDescriptorLine",
        BsmsErrorV2::InvalidRestrictionsLine => "InvalidRestrictionsLine",
        BsmsErrorV2::InvalidAddressLine => "InvalidAddressLine",
    }
}

fn expected_sd_display(error: WatchOnlySdExportErrorV2) -> &'static str {
    match error {
        WatchOnlySdExportErrorV2::FullMedia => "FullMedia",
        WatchOnlySdExportErrorV2::TemporaryCreateFailed => "TemporaryCreateFailed",
        WatchOnlySdExportErrorV2::WriteFailed => "WriteFailed",
        WatchOnlySdExportErrorV2::SyncFailed => "SyncFailed",
        WatchOnlySdExportErrorV2::CloseFailed => "CloseFailed",
        WatchOnlySdExportErrorV2::ReopenFailed => "ReopenFailed",
        WatchOnlySdExportErrorV2::VerificationMismatch => "VerificationMismatch",
        WatchOnlySdExportErrorV2::FilenameCollision => "FilenameCollision",
        WatchOnlySdExportErrorV2::RenameFailed => "RenameFailed",
    }
}
