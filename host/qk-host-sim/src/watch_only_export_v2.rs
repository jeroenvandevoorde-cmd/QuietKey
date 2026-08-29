//! v2 slice-6 HOST-only watch-only BSMS artifact and deterministic mock-SD model.
//!
//! This module is separate from the frozen M25 transaction-artifact types.
//! It performs no real media I/O, generates no randomness, and exposes no QR
//! transport.

use crate::bsms_v2::{
    bind_and_build_record_v2, BsmsBindingV2, BsmsErrorV2, BsmsRecordV2, BSMS_RECORD_BYTES_V2,
};
use crate::export::{SdExportError, SdExportFault};
use crate::transaction_sha256::sha256;
use core::fmt;
use qk_provisioning::ProvisioningArtifactsV2;
use std::collections::BTreeMap;

const NONCE_BYTES: usize = 16;
const NONCE_HEX_BYTES: usize = NONCE_BYTES * 2;
const FINAL_SUFFIX: &str = "-watch.bsms";
const TEMP_SUFFIX: &str = ".tmp";

/// v2 names for the unchanged QK-DEC-112 mock-SD failure categories.
pub type WatchOnlySdExportErrorV2 = SdExportError;

/// v2 names for the unchanged QK-DEC-112 injected lifecycle faults.
pub type WatchOnlySdExportFaultV2 = SdExportFault;

/// Closed v2 packaging-tier vocabulary for coordinator material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlyCoordinatorTierV2 {
    SimpleRecovery,
    Inheritance,
    QuantumShelter,
}

/// Failure while binding one watch-only artifact to provisioning facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlyExportErrorV2 {
    QuantumShelterDescriptorExport,
    Bsms(BsmsErrorV2),
    HashingInvariant,
}

impl fmt::Display for WatchOnlyExportErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuantumShelterDescriptorExport => {
                formatter.write_str("QuantumShelterDescriptorExport")
            }
            Self::Bsms(error) => fmt::Display::fmt(error, formatter),
            Self::HashingInvariant => formatter.write_str("watch-only artifact hashing invariant"),
        }
    }
}

impl std::error::Error for WatchOnlyExportErrorV2 {}

impl From<BsmsErrorV2> for WatchOnlyExportErrorV2 {
    fn from(error: BsmsErrorV2) -> Self {
        Self::Bsms(error)
    }
}

/// Exact immutable public facts attached to the BSMS artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchOnlyArtifactMetadataV2 {
    serialized_len: usize,
    sha256: [u8; 32],
    wallet_id: [u8; 32],
    first_addresses: [[u8; 62]; 2],
}

impl WatchOnlyArtifactMetadataV2 {
    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        self.serialized_len
    }

    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    /// Return receive then change index-zero addresses.
    #[must_use]
    pub const fn first_addresses(&self) -> [[u8; 62]; 2] {
        self.first_addresses
    }

    #[must_use]
    pub const fn first_receive_address(&self) -> [u8; 62] {
        self.first_addresses[0]
    }

    #[must_use]
    pub const fn first_change_address(&self) -> [u8; 62] {
        self.first_addresses[1]
    }
}

/// Opaque caller-supplied 128-bit watch-only export nonce.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WatchOnlyExportNonceV2([u8; NONCE_BYTES]);

impl WatchOnlyExportNonceV2 {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {
        Self(bytes)
    }
}

/// One exact generated lowercase-ASCII v2 filename.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WatchOnlySdFileNameV2(String);

impl WatchOnlySdFileNameV2 {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Final and temporary names for one nonce-bound BSMS artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchOnlySdArtifactNamesV2 {
    final_name: WatchOnlySdFileNameV2,
    temporary_name: WatchOnlySdFileNameV2,
}

impl WatchOnlySdArtifactNamesV2 {
    #[must_use]
    pub fn final_name(&self) -> &WatchOnlySdFileNameV2 {
        &self.final_name
    }

    #[must_use]
    pub fn temporary_name(&self) -> &WatchOnlySdFileNameV2 {
        &self.temporary_name
    }
}

/// Capability-only v2 artifact owner.
pub struct WatchOnlyExportArtifactsV2 {
    binding: BsmsBindingV2,
    tier: WatchOnlyCoordinatorTierV2,
    record: BsmsRecordV2,
    metadata: WatchOnlyArtifactMetadataV2,
}

impl WatchOnlyExportArtifactsV2 {
    /// Bind one exact BSMS record to an eligible provisioning result.
    pub fn from_provisioning(
        provisioning: &ProvisioningArtifactsV2,
        tier: WatchOnlyCoordinatorTierV2,
    ) -> Result<Self, WatchOnlyExportErrorV2> {
        if tier == WatchOnlyCoordinatorTierV2::QuantumShelter {
            return Err(WatchOnlyExportErrorV2::QuantumShelterDescriptorExport);
        }
        let (binding, record) = bind_and_build_record_v2(provisioning)?;
        let digest =
            sha256(&[record.bytes()]).map_err(|_| WatchOnlyExportErrorV2::HashingInvariant)?;
        let metadata = WatchOnlyArtifactMetadataV2 {
            serialized_len: BSMS_RECORD_BYTES_V2,
            sha256: digest,
            wallet_id: provisioning.wallet_id,
            first_addresses: [*record.receive_address(), *record.change_address()],
        };
        Ok(Self {
            binding,
            tier,
            record,
            metadata,
        })
    }

    #[must_use]
    pub const fn tier(&self) -> WatchOnlyCoordinatorTierV2 {
        self.tier
    }

    #[must_use]
    pub const fn artifact(&self) -> WatchOnlyBsmsArtifactV2<'_> {
        WatchOnlyBsmsArtifactV2 {
            record: &self.record,
            binding: &self.binding,
            metadata: self.metadata,
        }
    }
}

/// Typed watch-only BSMS artifact. It deliberately has no QR method.
#[derive(Clone, Copy)]
pub struct WatchOnlyBsmsArtifactV2<'a> {
    record: &'a BsmsRecordV2,
    binding: &'a BsmsBindingV2,
    metadata: WatchOnlyArtifactMetadataV2,
}

impl<'a> WatchOnlyBsmsArtifactV2<'a> {
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8; BSMS_RECORD_BYTES_V2] {
        self.record.bytes()
    }

    #[must_use]
    pub const fn metadata(&self) -> WatchOnlyArtifactMetadataV2 {
        self.metadata
    }

    /// Apply the same semantic verification used after mock-SD reopen.
    pub fn verify_reopened(&self, reopened: &[u8]) -> Result<(), BsmsErrorV2> {
        self.record.verify_reopened(reopened, self.binding)
    }

    /// Publish exactly this BSMS record through one mock-SD lifecycle.
    pub fn write_mock_sd(
        self,
        nonce: WatchOnlyExportNonceV2,
        filesystem: &mut WatchOnlyMockSdFilesystemV2,
        fault: Option<WatchOnlySdExportFaultV2>,
    ) -> Result<WatchOnlySdPublishedArtifactV2, WatchOnlySdExportErrorV2> {
        let names = names_for(nonce);
        publish_one(filesystem, self, &names, fault)?;
        Ok(WatchOnlySdPublishedArtifactV2 {
            metadata: self.metadata,
            names,
        })
    }
}

/// Metadata and names for one successfully published mock-SD BSMS artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchOnlySdPublishedArtifactV2 {
    metadata: WatchOnlyArtifactMetadataV2,
    names: WatchOnlySdArtifactNamesV2,
}

impl WatchOnlySdPublishedArtifactV2 {
    #[must_use]
    pub const fn metadata(&self) -> WatchOnlyArtifactMetadataV2 {
        self.metadata
    }

    #[must_use]
    pub fn names(&self) -> &WatchOnlySdArtifactNamesV2 {
        &self.names
    }
}

/// Observable kind of one deterministic watch-only mock namespace entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlyMockFileKindV2 {
    Existing,
    Temporary,
    Final,
}

struct WatchOnlyMockFileV2 {
    kind: WatchOnlyMockFileKindV2,
    bytes: Vec<u8>,
    synced: bool,
    closed: bool,
}

/// Exact lifecycle events emitted only after the corresponding transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlySdLifecycleEventV2 {
    TemporaryCreated,
    BytesWritten { bytes: usize, complete: bool },
    FileSynced,
    Closed,
    Reopened,
    Verified,
    Renamed,
}

/// Deterministic in-memory v2 namespace. It makes no real-filesystem claim.
#[derive(Default)]
pub struct WatchOnlyMockSdFilesystemV2 {
    files: BTreeMap<String, WatchOnlyMockFileV2>,
    events: Vec<WatchOnlySdLifecycleEventV2>,
}

impl WatchOnlyMockSdFilesystemV2 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed one pre-existing file. Existing names are never replaced.
    pub fn insert_existing(&mut self, name: &str, bytes: &[u8]) -> bool {
        if self.files.contains_key(name) {
            return false;
        }
        self.files.insert(
            name.to_owned(),
            WatchOnlyMockFileV2 {
                kind: WatchOnlyMockFileKindV2::Existing,
                bytes: bytes.to_vec(),
                synced: true,
                closed: true,
            },
        );
        true
    }

    #[must_use]
    pub fn file_bytes(&self, name: &WatchOnlySdFileNameV2) -> Option<&[u8]> {
        self.files
            .get(name.as_str())
            .map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn existing_file_bytes(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn file_kind(&self, name: &WatchOnlySdFileNameV2) -> Option<WatchOnlyMockFileKindV2> {
        self.files.get(name.as_str()).map(|file| file.kind)
    }

    #[must_use]
    pub fn events(&self) -> &[WatchOnlySdLifecycleEventV2] {
        &self.events
    }
}

fn names_for(nonce: WatchOnlyExportNonceV2) -> WatchOnlySdArtifactNamesV2 {
    let mut final_name = String::with_capacity(3 + NONCE_HEX_BYTES + FINAL_SUFFIX.len());
    final_name.push_str("qk-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in nonce.0 {
        final_name.push(char::from(HEX[usize::from(byte >> 4)]));
        final_name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    final_name.push_str(FINAL_SUFFIX);
    let mut temporary_name = String::with_capacity(final_name.len() + TEMP_SUFFIX.len());
    temporary_name.push_str(&final_name);
    temporary_name.push_str(TEMP_SUFFIX);
    WatchOnlySdArtifactNamesV2 {
        final_name: WatchOnlySdFileNameV2(final_name),
        temporary_name: WatchOnlySdFileNameV2(temporary_name),
    }
}

fn preflight(
    filesystem: &WatchOnlyMockSdFilesystemV2,
    names: &WatchOnlySdArtifactNamesV2,
) -> Result<(), WatchOnlySdExportErrorV2> {
    if filesystem.files.contains_key(names.final_name.as_str()) {
        return Err(WatchOnlySdExportErrorV2::FilenameCollision);
    }
    if filesystem.files.contains_key(names.temporary_name.as_str()) {
        return Err(WatchOnlySdExportErrorV2::TemporaryCreateFailed);
    }
    Ok(())
}

fn publish_one(
    filesystem: &mut WatchOnlyMockSdFilesystemV2,
    artifact: WatchOnlyBsmsArtifactV2<'_>,
    names: &WatchOnlySdArtifactNamesV2,
    fault: Option<WatchOnlySdExportFaultV2>,
) -> Result<(), WatchOnlySdExportErrorV2> {
    preflight(filesystem, names)?;
    if fault == Some(WatchOnlySdExportFaultV2::TemporaryCreateFailed) {
        return Err(WatchOnlySdExportErrorV2::TemporaryCreateFailed);
    }
    filesystem.files.insert(
        names.temporary_name.0.clone(),
        WatchOnlyMockFileV2 {
            kind: WatchOnlyMockFileKindV2::Temporary,
            bytes: Vec::new(),
            synced: false,
            closed: false,
        },
    );
    filesystem
        .events
        .push(WatchOnlySdLifecycleEventV2::TemporaryCreated);

    if fault == Some(WatchOnlySdExportFaultV2::FullMedia) {
        return Err(WatchOnlySdExportErrorV2::FullMedia);
    }
    let temporary = filesystem
        .files
        .get_mut(names.temporary_name.as_str())
        .ok_or(WatchOnlySdExportErrorV2::TemporaryCreateFailed)?;
    if fault == Some(WatchOnlySdExportFaultV2::WriteFailed) {
        let prefix_len = artifact.bytes().len() / 2;
        temporary
            .bytes
            .extend_from_slice(&artifact.bytes()[..prefix_len]);
        filesystem
            .events
            .push(WatchOnlySdLifecycleEventV2::BytesWritten {
                bytes: prefix_len,
                complete: false,
            });
        return Err(WatchOnlySdExportErrorV2::WriteFailed);
    }
    temporary.bytes.extend_from_slice(artifact.bytes());
    filesystem
        .events
        .push(WatchOnlySdLifecycleEventV2::BytesWritten {
            bytes: artifact.bytes().len(),
            complete: true,
        });

    if fault == Some(WatchOnlySdExportFaultV2::SyncFailed) {
        return Err(WatchOnlySdExportErrorV2::SyncFailed);
    }
    temporary.synced = true;
    filesystem
        .events
        .push(WatchOnlySdLifecycleEventV2::FileSynced);

    if fault == Some(WatchOnlySdExportFaultV2::CloseFailed) {
        return Err(WatchOnlySdExportErrorV2::CloseFailed);
    }
    temporary.closed = true;
    filesystem.events.push(WatchOnlySdLifecycleEventV2::Closed);

    if fault == Some(WatchOnlySdExportFaultV2::ReopenFailed) {
        return Err(WatchOnlySdExportErrorV2::ReopenFailed);
    }
    filesystem
        .events
        .push(WatchOnlySdLifecycleEventV2::Reopened);

    if fault == Some(WatchOnlySdExportFaultV2::VerificationMismatch)
        || !metadata_matches(artifact.metadata, &temporary.bytes)
        || artifact.verify_reopened(&temporary.bytes).is_err()
    {
        return Err(WatchOnlySdExportErrorV2::VerificationMismatch);
    }
    filesystem
        .events
        .push(WatchOnlySdLifecycleEventV2::Verified);

    if fault == Some(WatchOnlySdExportFaultV2::RenameFailed) {
        return Err(WatchOnlySdExportErrorV2::RenameFailed);
    }
    if filesystem.files.contains_key(names.final_name.as_str()) {
        return Err(WatchOnlySdExportErrorV2::FilenameCollision);
    }
    let mut published = filesystem
        .files
        .remove(names.temporary_name.as_str())
        .ok_or(WatchOnlySdExportErrorV2::RenameFailed)?;
    published.kind = WatchOnlyMockFileKindV2::Final;
    filesystem
        .files
        .insert(names.final_name.0.clone(), published);
    filesystem.events.push(WatchOnlySdLifecycleEventV2::Renamed);
    Ok(())
}

fn metadata_matches(metadata: WatchOnlyArtifactMetadataV2, bytes: &[u8]) -> bool {
    metadata.serialized_len == bytes.len()
        && matches!(sha256(&[bytes]), Ok(digest) if digest == metadata.sha256)
}
