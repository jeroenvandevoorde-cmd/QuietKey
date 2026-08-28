//! M28 HOST-only watch-only BSMS artifact and deterministic mock-SD model.
//!
//! This module is separate from the frozen M25 transaction-artifact types.
//! It performs no real media I/O, generates no randomness, and exposes no QR
//! transport.

use crate::bsms::{build_record, BsmsError, BsmsRecord, BSMS_RECORD_BYTES};
use crate::export::{KitTier, SdExportError, SdExportFault};
use crate::transaction_sha256::sha256;
use core::fmt;
use qk_provisioning::ProvisioningArtifacts;
use std::collections::BTreeMap;

const NONCE_BYTES: usize = 16;
const NONCE_HEX_BYTES: usize = NONCE_BYTES * 2;
const FINAL_SUFFIX: &str = "-watch.bsms";
const TEMP_SUFFIX: &str = ".tmp";

/// M28 names for the unchanged QK-DEC-112 mock-SD failure categories.
pub type WatchOnlySdExportError = SdExportError;

/// M28 names for the unchanged QK-DEC-112 injected lifecycle faults.
pub type WatchOnlySdExportFault = SdExportFault;

/// Failure while binding one watch-only artifact to provisioning facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlyExportError {
    QuantumShelterDescriptorExport,
    Bsms(BsmsError),
    HashingInvariant,
}

impl fmt::Display for WatchOnlyExportError {
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

impl std::error::Error for WatchOnlyExportError {}

impl From<BsmsError> for WatchOnlyExportError {
    fn from(error: BsmsError) -> Self {
        Self::Bsms(error)
    }
}

/// Exact immutable public facts attached to the BSMS artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchOnlyArtifactMetadata {
    serialized_len: usize,
    sha256: [u8; 32],
    wallet_id: [u8; 32],
    first_addresses: [[u8; 62]; 2],
}

impl WatchOnlyArtifactMetadata {
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
pub struct WatchOnlyExportNonce([u8; NONCE_BYTES]);

impl WatchOnlyExportNonce {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {
        Self(bytes)
    }
}

/// One exact generated lowercase-ASCII M28 filename.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WatchOnlySdFileName(String);

impl WatchOnlySdFileName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Final and temporary names for one nonce-bound BSMS artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchOnlySdArtifactNames {
    final_name: WatchOnlySdFileName,
    temporary_name: WatchOnlySdFileName,
}

impl WatchOnlySdArtifactNames {
    #[must_use]
    pub fn final_name(&self) -> &WatchOnlySdFileName {
        &self.final_name
    }

    #[must_use]
    pub fn temporary_name(&self) -> &WatchOnlySdFileName {
        &self.temporary_name
    }
}

/// Capability-only M28 artifact owner.
pub struct WatchOnlyExportArtifacts {
    provisioning: ProvisioningArtifacts,
    tier: KitTier,
    record: BsmsRecord,
    metadata: WatchOnlyArtifactMetadata,
}

impl WatchOnlyExportArtifacts {
    /// Bind one exact BSMS record to an eligible provisioning result.
    pub fn from_provisioning(
        provisioning: &ProvisioningArtifacts,
        tier: KitTier,
    ) -> Result<Self, WatchOnlyExportError> {
        if tier == KitTier::QuantumShelter {
            return Err(WatchOnlyExportError::QuantumShelterDescriptorExport);
        }
        let record = build_record(provisioning)?;
        let digest =
            sha256(&[record.bytes()]).map_err(|_| WatchOnlyExportError::HashingInvariant)?;
        let metadata = WatchOnlyArtifactMetadata {
            serialized_len: BSMS_RECORD_BYTES,
            sha256: digest,
            wallet_id: provisioning.wallet_id,
            first_addresses: [*record.receive_address(), *record.change_address()],
        };
        Ok(Self {
            provisioning: *provisioning,
            tier,
            record,
            metadata,
        })
    }

    #[must_use]
    pub const fn tier(&self) -> KitTier {
        self.tier
    }

    #[must_use]
    pub const fn artifact(&self) -> WatchOnlyBsmsArtifact<'_> {
        WatchOnlyBsmsArtifact {
            record: &self.record,
            provisioning: &self.provisioning,
            metadata: self.metadata,
        }
    }
}

/// Typed watch-only BSMS artifact. It deliberately has no QR method.
#[derive(Clone, Copy)]
pub struct WatchOnlyBsmsArtifact<'a> {
    record: &'a BsmsRecord,
    provisioning: &'a ProvisioningArtifacts,
    metadata: WatchOnlyArtifactMetadata,
}

impl<'a> WatchOnlyBsmsArtifact<'a> {
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8; BSMS_RECORD_BYTES] {
        self.record.bytes()
    }

    #[must_use]
    pub const fn metadata(&self) -> WatchOnlyArtifactMetadata {
        self.metadata
    }

    /// Apply the same semantic verification used after mock-SD reopen.
    pub fn verify_reopened(&self, reopened: &[u8]) -> Result<(), BsmsError> {
        self.record.verify_reopened(reopened, self.provisioning)
    }

    /// Publish exactly this BSMS record through one mock-SD lifecycle.
    pub fn write_mock_sd(
        self,
        nonce: WatchOnlyExportNonce,
        filesystem: &mut WatchOnlyMockSdFilesystem,
        fault: Option<WatchOnlySdExportFault>,
    ) -> Result<WatchOnlySdPublishedArtifact, WatchOnlySdExportError> {
        let names = names_for(nonce);
        publish_one(filesystem, self, &names, fault)?;
        Ok(WatchOnlySdPublishedArtifact {
            metadata: self.metadata,
            names,
        })
    }
}

/// Metadata and names for one successfully published mock-SD BSMS artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchOnlySdPublishedArtifact {
    metadata: WatchOnlyArtifactMetadata,
    names: WatchOnlySdArtifactNames,
}

impl WatchOnlySdPublishedArtifact {
    #[must_use]
    pub const fn metadata(&self) -> WatchOnlyArtifactMetadata {
        self.metadata
    }

    #[must_use]
    pub fn names(&self) -> &WatchOnlySdArtifactNames {
        &self.names
    }
}

/// Observable kind of one deterministic watch-only mock namespace entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlyMockFileKind {
    Existing,
    Temporary,
    Final,
}

struct WatchOnlyMockFile {
    kind: WatchOnlyMockFileKind,
    bytes: Vec<u8>,
    synced: bool,
    closed: bool,
}

/// Exact lifecycle events emitted only after the corresponding transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchOnlySdLifecycleEvent {
    TemporaryCreated,
    BytesWritten { bytes: usize, complete: bool },
    FileSynced,
    Closed,
    Reopened,
    Verified,
    Renamed,
}

/// Deterministic in-memory M28 namespace. It makes no real-filesystem claim.
#[derive(Default)]
pub struct WatchOnlyMockSdFilesystem {
    files: BTreeMap<String, WatchOnlyMockFile>,
    events: Vec<WatchOnlySdLifecycleEvent>,
}

impl WatchOnlyMockSdFilesystem {
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
            WatchOnlyMockFile {
                kind: WatchOnlyMockFileKind::Existing,
                bytes: bytes.to_vec(),
                synced: true,
                closed: true,
            },
        );
        true
    }

    #[must_use]
    pub fn file_bytes(&self, name: &WatchOnlySdFileName) -> Option<&[u8]> {
        self.files
            .get(name.as_str())
            .map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn existing_file_bytes(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn file_kind(&self, name: &WatchOnlySdFileName) -> Option<WatchOnlyMockFileKind> {
        self.files.get(name.as_str()).map(|file| file.kind)
    }

    #[must_use]
    pub fn events(&self) -> &[WatchOnlySdLifecycleEvent] {
        &self.events
    }
}

fn names_for(nonce: WatchOnlyExportNonce) -> WatchOnlySdArtifactNames {
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
    WatchOnlySdArtifactNames {
        final_name: WatchOnlySdFileName(final_name),
        temporary_name: WatchOnlySdFileName(temporary_name),
    }
}

fn preflight(
    filesystem: &WatchOnlyMockSdFilesystem,
    names: &WatchOnlySdArtifactNames,
) -> Result<(), WatchOnlySdExportError> {
    if filesystem.files.contains_key(names.final_name.as_str()) {
        return Err(WatchOnlySdExportError::FilenameCollision);
    }
    if filesystem.files.contains_key(names.temporary_name.as_str()) {
        return Err(WatchOnlySdExportError::TemporaryCreateFailed);
    }
    Ok(())
}

fn publish_one(
    filesystem: &mut WatchOnlyMockSdFilesystem,
    artifact: WatchOnlyBsmsArtifact<'_>,
    names: &WatchOnlySdArtifactNames,
    fault: Option<WatchOnlySdExportFault>,
) -> Result<(), WatchOnlySdExportError> {
    preflight(filesystem, names)?;
    if fault == Some(WatchOnlySdExportFault::TemporaryCreateFailed) {
        return Err(WatchOnlySdExportError::TemporaryCreateFailed);
    }
    filesystem.files.insert(
        names.temporary_name.0.clone(),
        WatchOnlyMockFile {
            kind: WatchOnlyMockFileKind::Temporary,
            bytes: Vec::new(),
            synced: false,
            closed: false,
        },
    );
    filesystem
        .events
        .push(WatchOnlySdLifecycleEvent::TemporaryCreated);

    if fault == Some(WatchOnlySdExportFault::FullMedia) {
        return Err(WatchOnlySdExportError::FullMedia);
    }
    let temporary = filesystem
        .files
        .get_mut(names.temporary_name.as_str())
        .ok_or(WatchOnlySdExportError::TemporaryCreateFailed)?;
    if fault == Some(WatchOnlySdExportFault::WriteFailed) {
        let prefix_len = artifact.bytes().len() / 2;
        temporary
            .bytes
            .extend_from_slice(&artifact.bytes()[..prefix_len]);
        filesystem
            .events
            .push(WatchOnlySdLifecycleEvent::BytesWritten {
                bytes: prefix_len,
                complete: false,
            });
        return Err(WatchOnlySdExportError::WriteFailed);
    }
    temporary.bytes.extend_from_slice(artifact.bytes());
    filesystem
        .events
        .push(WatchOnlySdLifecycleEvent::BytesWritten {
            bytes: artifact.bytes().len(),
            complete: true,
        });

    if fault == Some(WatchOnlySdExportFault::SyncFailed) {
        return Err(WatchOnlySdExportError::SyncFailed);
    }
    temporary.synced = true;
    filesystem
        .events
        .push(WatchOnlySdLifecycleEvent::FileSynced);

    if fault == Some(WatchOnlySdExportFault::CloseFailed) {
        return Err(WatchOnlySdExportError::CloseFailed);
    }
    temporary.closed = true;
    filesystem.events.push(WatchOnlySdLifecycleEvent::Closed);

    if fault == Some(WatchOnlySdExportFault::ReopenFailed) {
        return Err(WatchOnlySdExportError::ReopenFailed);
    }
    filesystem.events.push(WatchOnlySdLifecycleEvent::Reopened);

    if fault == Some(WatchOnlySdExportFault::VerificationMismatch)
        || !metadata_matches(artifact.metadata, &temporary.bytes)
        || artifact.verify_reopened(&temporary.bytes).is_err()
    {
        return Err(WatchOnlySdExportError::VerificationMismatch);
    }
    filesystem.events.push(WatchOnlySdLifecycleEvent::Verified);

    if fault == Some(WatchOnlySdExportFault::RenameFailed) {
        return Err(WatchOnlySdExportError::RenameFailed);
    }
    if filesystem.files.contains_key(names.final_name.as_str()) {
        return Err(WatchOnlySdExportError::FilenameCollision);
    }
    let mut published = filesystem
        .files
        .remove(names.temporary_name.as_str())
        .ok_or(WatchOnlySdExportError::RenameFailed)?;
    published.kind = WatchOnlyMockFileKind::Final;
    filesystem
        .files
        .insert(names.final_name.0.clone(), published);
    filesystem.events.push(WatchOnlySdLifecycleEvent::Renamed);
    Ok(())
}

fn metadata_matches(metadata: WatchOnlyArtifactMetadata, bytes: &[u8]) -> bool {
    metadata.serialized_len == bytes.len()
        && matches!(sha256(&[bytes]), Ok(digest) if digest == metadata.sha256)
}
