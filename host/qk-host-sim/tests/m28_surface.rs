//! M28 watch-only artifact surface, fact, and transport fences.

#[path = "support/m28.rs"]
mod support;

use qk_host_sim::{
    BsmsError, KitTier, WatchOnlyArtifactMetadata, WatchOnlyBsmsArtifact, WatchOnlyExportArtifacts,
    WatchOnlyExportError, WatchOnlyExportNonce, WatchOnlyMockFileKind, WatchOnlyMockSdFilesystem,
    WatchOnlySdArtifactNames, WatchOnlySdExportError, WatchOnlySdExportFault, WatchOnlySdFileName,
    WatchOnlySdLifecycleEvent, WatchOnlySdPublishedArtifact, BSMS_RECORD_BYTES,
};
use support::{bsms_bytes, field, hex_array, nonce, owner, sha256};

const LIB: &str = include_str!("../src/lib.rs");
const BSMS: &str = include_str!("../src/bsms.rs");
const WATCH_ONLY: &str = include_str!("../src/watch_only_export.rs");

#[test]
fn public_surface_is_the_closed_bsms_artifact_and_mock_sd_boundary() {
    let public_lines: Vec<&str> = WATCH_ONLY
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub type WatchOnlySdExportError = SdExportError;",
            "pub type WatchOnlySdExportFault = SdExportFault;",
            "pub enum WatchOnlyExportError {",
            "pub struct WatchOnlyArtifactMetadata {",
            "pub const fn serialized_len(&self) -> usize {",
            "pub const fn sha256(&self) -> [u8; 32] {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn first_addresses(&self) -> [[u8; 62]; 2] {",
            "pub const fn first_receive_address(&self) -> [u8; 62] {",
            "pub const fn first_change_address(&self) -> [u8; 62] {",
            "pub struct WatchOnlyExportNonce([u8; NONCE_BYTES]);",
            "pub const fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {",
            "pub struct WatchOnlySdFileName(String);",
            "pub fn as_str(&self) -> &str {",
            "pub struct WatchOnlySdArtifactNames {",
            "pub fn final_name(&self) -> &WatchOnlySdFileName {",
            "pub fn temporary_name(&self) -> &WatchOnlySdFileName {",
            "pub struct WatchOnlyExportArtifacts {",
            "pub fn from_provisioning(",
            "pub const fn tier(&self) -> KitTier {",
            "pub const fn artifact(&self) -> WatchOnlyBsmsArtifact<'_> {",
            "pub struct WatchOnlyBsmsArtifact<'a> {",
            "pub const fn bytes(&self) -> &'a [u8; BSMS_RECORD_BYTES] {",
            "pub const fn metadata(&self) -> WatchOnlyArtifactMetadata {",
            "pub fn verify_reopened(&self, reopened: &[u8]) -> Result<(), BsmsError> {",
            "pub fn write_mock_sd(",
            "pub struct WatchOnlySdPublishedArtifact {",
            "pub const fn metadata(&self) -> WatchOnlyArtifactMetadata {",
            "pub fn names(&self) -> &WatchOnlySdArtifactNames {",
            "pub enum WatchOnlyMockFileKind {",
            "pub enum WatchOnlySdLifecycleEvent {",
            "pub struct WatchOnlyMockSdFilesystem {",
            "pub fn new() -> Self {",
            "pub fn insert_existing(&mut self, name: &str, bytes: &[u8]) -> bool {",
            "pub fn file_bytes(&self, name: &WatchOnlySdFileName) -> Option<&[u8]> {",
            "pub fn existing_file_bytes(&self, name: &str) -> Option<&[u8]> {",
            "pub fn file_kind(&self, name: &WatchOnlySdFileName) -> Option<WatchOnlyMockFileKind> {",
            "pub fn events(&self) -> &[WatchOnlySdLifecycleEvent] {",
        ],
        "complete M28 public item and method surface"
    );

    assert!(LIB.contains("mod bsms;"));
    assert!(LIB.contains("mod watch_only_export;"));
    assert!(!LIB.contains("pub mod bsms;"));
    assert!(!LIB.contains("pub mod watch_only_export;"));
    assert!(LIB.contains("pub use bsms::{BsmsError, BSMS_RECORD_BYTES};"));
    assert!(!LIB.contains("pub use bsms::{BsmsError, BsmsRecord"));

    let _: Option<WatchOnlyArtifactMetadata> = None;
    let _: Option<WatchOnlyBsmsArtifact<'_>> = None;
    let _: Option<WatchOnlyExportArtifacts> = None;
    let _: Option<WatchOnlyExportNonce> = None;
    let _: Option<WatchOnlyMockFileKind> = None;
    let _: Option<WatchOnlyMockSdFilesystem> = None;
    let _: Option<WatchOnlySdArtifactNames> = None;
    let _: Option<WatchOnlySdFileName> = None;
    let _: Option<WatchOnlySdLifecycleEvent> = None;
    let _: Option<WatchOnlySdPublishedArtifact> = None;
}

#[test]
fn served_tiers_expose_exact_bound_artifact_facts_and_quantum_rejects() {
    let expected = bsms_bytes();
    let expected_hash = sha256(&expected);
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

    for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
        let owner = owner(tier).expect("served M28 tier");
        assert_eq!(owner.tier(), tier);
        let artifact = owner.artifact();
        assert_eq!(artifact.bytes().as_slice(), expected);
        let metadata = artifact.metadata();
        assert_eq!(metadata.serialized_len(), BSMS_RECORD_BYTES);
        assert_eq!(metadata.sha256(), expected_hash);
        assert_eq!(metadata.wallet_id(), hex_array(field("wallet_id")));
        assert_eq!(metadata.first_addresses(), expected_addresses);
        assert_eq!(metadata.first_receive_address(), expected_addresses[0]);
        assert_eq!(metadata.first_change_address(), expected_addresses[1]);
        assert_eq!(artifact.verify_reopened(&expected), Ok(()));

        let mut filesystem = WatchOnlyMockSdFilesystem::new();
        let published = artifact
            .write_mock_sd(nonce(), &mut filesystem, None)
            .expect("served M28 SD publication");
        assert_eq!(published.metadata(), metadata);
        assert_eq!(published.names().final_name().as_str(), field("final_name"));
        assert_eq!(
            published.names().temporary_name().as_str(),
            field("temporary_name")
        );
        assert_eq!(
            filesystem.file_kind(published.names().final_name()),
            Some(WatchOnlyMockFileKind::Final)
        );
        assert_eq!(
            filesystem.file_bytes(published.names().final_name()),
            Some(expected.as_slice())
        );
    }

    let quantum = owner(KitTier::QuantumShelter);
    assert!(matches!(
        quantum,
        Err(WatchOnlyExportError::QuantumShelterDescriptorExport)
    ));
}

#[test]
fn every_closed_error_has_exact_stable_display_text() {
    assert_error::<BsmsError>();
    assert_error::<WatchOnlyExportError>();
    assert_error::<WatchOnlySdExportError>();

    let bsms_errors = [
        BsmsError::InvalidDescriptorPair,
        BsmsError::WalletIdMismatch,
        BsmsError::FirstScriptMismatch,
        BsmsError::FirstAddressMismatch,
        BsmsError::DescriptorRoundTripMismatch,
        BsmsError::InvalidRecordLength,
        BsmsError::InvalidRecordEncoding,
        BsmsError::InvalidVersionLine,
        BsmsError::InvalidDescriptorLine,
        BsmsError::InvalidRestrictionsLine,
        BsmsError::InvalidAddressLine,
    ];
    for error in bsms_errors {
        assert_eq!(error.to_string(), expected_bsms_display(error));
        assert_eq!(
            WatchOnlyExportError::Bsms(error).to_string(),
            expected_bsms_display(error)
        );
    }

    let export_errors = [
        WatchOnlyExportError::QuantumShelterDescriptorExport,
        WatchOnlyExportError::Bsms(BsmsError::InvalidDescriptorPair),
        WatchOnlyExportError::HashingInvariant,
    ];
    for error in export_errors {
        assert_eq!(error.to_string(), expected_export_display(error));
    }

    let sd_errors = [
        WatchOnlySdExportError::FullMedia,
        WatchOnlySdExportError::TemporaryCreateFailed,
        WatchOnlySdExportError::WriteFailed,
        WatchOnlySdExportError::SyncFailed,
        WatchOnlySdExportError::CloseFailed,
        WatchOnlySdExportError::ReopenFailed,
        WatchOnlySdExportError::VerificationMismatch,
        WatchOnlySdExportError::FilenameCollision,
        WatchOnlySdExportError::RenameFailed,
    ];
    for error in sd_errors {
        assert_eq!(error.to_string(), expected_sd_display(error));
    }

    for fault in [
        WatchOnlySdExportFault::FullMedia,
        WatchOnlySdExportFault::TemporaryCreateFailed,
        WatchOnlySdExportFault::WriteFailed,
        WatchOnlySdExportFault::SyncFailed,
        WatchOnlySdExportFault::CloseFailed,
        WatchOnlySdExportFault::ReopenFailed,
        WatchOnlySdExportFault::VerificationMismatch,
        WatchOnlySdExportFault::RenameFailed,
    ] {
        assert!(!fault_name(fault).is_empty());
    }
}

#[test]
fn descriptor_export_has_no_qr_bbqr_or_real_io_surface() {
    let artifact_impl = WATCH_ONLY
        .split_once("impl<'a> WatchOnlyBsmsArtifact<'a> {")
        .expect("artifact implementation")
        .1
        .split_once("\n}\n\n/// Metadata and names")
        .expect("artifact implementation boundary")
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
    ] {
        assert!(!WATCH_ONLY.contains(forbidden), "scope fence {forbidden}");
    }
    assert!(!BSMS.contains("qk_bbqr"));
    assert!(!BSMS.contains("pub fn bbqr("));
    assert!(!BSMS.contains("pub fn qr("));
}

fn assert_error<E: std::error::Error>() {}

fn expected_bsms_display(error: BsmsError) -> &'static str {
    match error {
        BsmsError::InvalidDescriptorPair => "InvalidDescriptorPair",
        BsmsError::WalletIdMismatch => "WalletIdMismatch",
        BsmsError::FirstScriptMismatch => "FirstScriptMismatch",
        BsmsError::FirstAddressMismatch => "FirstAddressMismatch",
        BsmsError::DescriptorRoundTripMismatch => "DescriptorRoundTripMismatch",
        BsmsError::InvalidRecordLength => "InvalidRecordLength",
        BsmsError::InvalidRecordEncoding => "InvalidRecordEncoding",
        BsmsError::InvalidVersionLine => "InvalidVersionLine",
        BsmsError::InvalidDescriptorLine => "InvalidDescriptorLine",
        BsmsError::InvalidRestrictionsLine => "InvalidRestrictionsLine",
        BsmsError::InvalidAddressLine => "InvalidAddressLine",
    }
}

fn expected_export_display(error: WatchOnlyExportError) -> &'static str {
    match error {
        WatchOnlyExportError::QuantumShelterDescriptorExport => "QuantumShelterDescriptorExport",
        WatchOnlyExportError::Bsms(error) => expected_bsms_display(error),
        WatchOnlyExportError::HashingInvariant => "watch-only artifact hashing invariant",
    }
}

fn expected_sd_display(error: WatchOnlySdExportError) -> &'static str {
    match error {
        WatchOnlySdExportError::FullMedia => "FullMedia",
        WatchOnlySdExportError::TemporaryCreateFailed => "TemporaryCreateFailed",
        WatchOnlySdExportError::WriteFailed => "WriteFailed",
        WatchOnlySdExportError::SyncFailed => "SyncFailed",
        WatchOnlySdExportError::CloseFailed => "CloseFailed",
        WatchOnlySdExportError::ReopenFailed => "ReopenFailed",
        WatchOnlySdExportError::VerificationMismatch => "VerificationMismatch",
        WatchOnlySdExportError::FilenameCollision => "FilenameCollision",
        WatchOnlySdExportError::RenameFailed => "RenameFailed",
    }
}

fn fault_name(fault: WatchOnlySdExportFault) -> &'static str {
    match fault {
        WatchOnlySdExportFault::FullMedia => "FullMedia",
        WatchOnlySdExportFault::TemporaryCreateFailed => "TemporaryCreateFailed",
        WatchOnlySdExportFault::WriteFailed => "WriteFailed",
        WatchOnlySdExportFault::SyncFailed => "SyncFailed",
        WatchOnlySdExportFault::CloseFailed => "CloseFailed",
        WatchOnlySdExportFault::ReopenFailed => "ReopenFailed",
        WatchOnlySdExportFault::VerificationMismatch => "VerificationMismatch",
        WatchOnlySdExportFault::RenameFailed => "RenameFailed",
    }
}
