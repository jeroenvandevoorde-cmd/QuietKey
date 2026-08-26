//! Capability-only M25 HOST export boundary and deterministic mock SD model.

use crate::transaction_sha256::{sha256, sha256d};
use crate::FinalizedTransaction;
use core::fmt;
use qk_bbqr::{encode_frame, encoded_part_count, BbqrError, MAX_FRAME_TEXT_BYTES};
use qk_psbt::{canonical_serialize, parse, InputSource};
use std::collections::BTreeMap;

const NONCE_BYTES: usize = 16;
const NONCE_HEX_BYTES: usize = NONCE_BYTES * 2;
const PSBT_FINAL_SUFFIX: &str = "-final.psbt";
const RAW_FINAL_SUFFIX: &str = "-final.tx";
const TEMP_SUFFIX: &str = ".tmp";

/// Ratified v1 kit tier controlling which M25 artifacts are exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitTier {
    SimpleRecovery,
    Inheritance,
    QuantumShelter,
}

/// Closed artifact-kind vocabulary for M25.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExportArtifactKind {
    FinalizedPsbt,
    RawTransaction,
}

/// Failure while binding facts from an already checked M24 capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactBindingError {
    InvalidFinalizedArtifact,
    AllocationFailed,
}

impl fmt::Display for ArtifactBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFinalizedArtifact => "invalid finalized artifact",
            Self::AllocationFailed => "artifact binding allocation failed",
        })
    }
}

impl std::error::Error for ArtifactBindingError {}

/// Exact immutable facts attached to one artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdArtifactMetadata {
    kind: ExportArtifactKind,
    serialized_len: usize,
    sha256: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl SdArtifactMetadata {
    #[must_use]
    pub const fn kind(&self) -> ExportArtifactKind {
        self.kind
    }

    #[must_use]
    pub const fn serialized_len(&self) -> usize {
        self.serialized_len
    }

    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }
}

/// Opaque caller-supplied 128-bit export nonce. M25 never creates one.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ExportNonce([u8; NONCE_BYTES]);

impl ExportNonce {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_BYTES]) -> Self {
        Self(bytes)
    }
}

/// One exact generated lowercase-ASCII M25 filename.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SdFileName(String);

impl SdFileName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Final and temporary names for one nonce-bound artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdArtifactNames {
    final_name: SdFileName,
    temporary_name: SdFileName,
}

impl SdArtifactNames {
    #[must_use]
    pub fn final_name(&self) -> &SdFileName {
        &self.final_name
    }

    #[must_use]
    pub fn temporary_name(&self) -> &SdFileName {
        &self.temporary_name
    }
}

/// Typed finalized-PSBT view. Only this type exposes BBQr file-type-P framing.
#[derive(Clone, Copy)]
pub struct FinalizedPsbtArtifact<'a> {
    bytes: &'a [u8],
    metadata: SdArtifactMetadata,
}

impl<'a> FinalizedPsbtArtifact<'a> {
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> SdArtifactMetadata {
        self.metadata
    }

    /// Start sequential uncompressed Base32 file-type-P framing.
    pub fn bbqr(self, non_final_part_len: usize) -> Result<SequentialPsbtBbqr<'a>, BbqrError> {
        SequentialPsbtBbqr::new(self.bytes, non_final_part_len)
    }

    /// Publish exactly this finalized PSBT through one mock-SD lifecycle.
    pub fn write_mock_sd(
        self,
        nonce: ExportNonce,
        filesystem: &mut MockSdFilesystem,
        fault: Option<SdExportFault>,
    ) -> Result<SdPublishedArtifact, SdExportError> {
        write_one(
            filesystem,
            ExportArtifactKind::FinalizedPsbt,
            self.bytes,
            self.metadata,
            names_for(ExportArtifactKind::FinalizedPsbt, nonce),
            fault,
        )
    }
}

/// Typed raw-transaction view. It intentionally has no BBQr method.
#[derive(Clone, Copy)]
pub struct RawTransactionArtifact<'a> {
    bytes: &'a [u8],
    metadata: SdArtifactMetadata,
}

impl<'a> RawTransactionArtifact<'a> {
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> SdArtifactMetadata {
        self.metadata
    }

    /// Publish exactly this raw transaction through one mock-SD lifecycle.
    pub fn write_mock_sd(
        self,
        nonce: ExportNonce,
        filesystem: &mut MockSdFilesystem,
        fault: Option<SdExportFault>,
    ) -> Result<SdPublishedArtifact, SdExportError> {
        write_one(
            filesystem,
            ExportArtifactKind::RawTransaction,
            self.bytes,
            self.metadata,
            names_for(ExportArtifactKind::RawTransaction, nonce),
            fault,
        )
    }
}

/// Tier-closed artifact exposure. Quantum Shelter has no PSBT field.
pub enum TierArtifacts<'a> {
    SimpleRecovery {
        finalized_psbt: FinalizedPsbtArtifact<'a>,
        raw_transaction: RawTransactionArtifact<'a>,
    },
    Inheritance {
        finalized_psbt: FinalizedPsbtArtifact<'a>,
        raw_transaction: RawTransactionArtifact<'a>,
    },
    QuantumShelter {
        raw_transaction: RawTransactionArtifact<'a>,
    },
}

/// Capability-only M25 artifact owner. Arbitrary bytes cannot construct it.
pub struct ExportArtifacts {
    finalized: FinalizedTransaction,
    tier: KitTier,
    psbt_metadata: SdArtifactMetadata,
    raw_metadata: SdArtifactMetadata,
}

impl ExportArtifacts {
    /// Consume a checked M24 result and bind exact artifact facts.
    pub fn from_finalized(
        finalized: FinalizedTransaction,
        tier: KitTier,
    ) -> Result<Self, ArtifactBindingError> {
        let txid = finalized.txid();
        let wtxid = finalized.wtxid();
        let psbt_metadata = bind_metadata(
            ExportArtifactKind::FinalizedPsbt,
            finalized.finalized_psbt(),
            txid,
            wtxid,
        )?;
        let raw_metadata = bind_metadata(
            ExportArtifactKind::RawTransaction,
            finalized.raw_transaction(),
            txid,
            wtxid,
        )?;
        verify_finalized_pair(&finalized, psbt_metadata, raw_metadata)?;
        Ok(Self {
            finalized,
            tier,
            psbt_metadata,
            raw_metadata,
        })
    }

    #[must_use]
    pub const fn tier(&self) -> KitTier {
        self.tier
    }

    #[must_use]
    pub fn artifacts(&self) -> TierArtifacts<'_> {
        let psbt = FinalizedPsbtArtifact {
            bytes: self.finalized.finalized_psbt(),
            metadata: self.psbt_metadata,
        };
        let raw = RawTransactionArtifact {
            bytes: self.finalized.raw_transaction(),
            metadata: self.raw_metadata,
        };
        match self.tier {
            KitTier::SimpleRecovery => TierArtifacts::SimpleRecovery {
                finalized_psbt: psbt,
                raw_transaction: raw,
            },
            KitTier::Inheritance => TierArtifacts::Inheritance {
                finalized_psbt: psbt,
                raw_transaction: raw,
            },
            KitTier::QuantumShelter => TierArtifacts::QuantumShelter {
                raw_transaction: raw,
            },
        }
    }
}

/// Metadata for one successfully published mock-SD artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdPublishedArtifact {
    metadata: SdArtifactMetadata,
    names: SdArtifactNames,
}

impl SdPublishedArtifact {
    #[must_use]
    pub const fn metadata(&self) -> SdArtifactMetadata {
        self.metadata
    }

    #[must_use]
    pub fn names(&self) -> &SdArtifactNames {
        &self.names
    }
}

/// Exact closed QK-DEC-112 mock-SD failure set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdExportError {
    FullMedia,
    TemporaryCreateFailed,
    WriteFailed,
    SyncFailed,
    CloseFailed,
    ReopenFailed,
    VerificationMismatch,
    FilenameCollision,
    RenameFailed,
}

impl fmt::Display for SdExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FullMedia => "FullMedia",
            Self::TemporaryCreateFailed => "TemporaryCreateFailed",
            Self::WriteFailed => "WriteFailed",
            Self::SyncFailed => "SyncFailed",
            Self::CloseFailed => "CloseFailed",
            Self::ReopenFailed => "ReopenFailed",
            Self::VerificationMismatch => "VerificationMismatch",
            Self::FilenameCollision => "FilenameCollision",
            Self::RenameFailed => "RenameFailed",
        })
    }
}

impl std::error::Error for SdExportError {}

/// Deterministic injected failure at one per-artifact lifecycle edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdExportFault {
    FullMedia,
    TemporaryCreateFailed,
    WriteFailed,
    SyncFailed,
    CloseFailed,
    ReopenFailed,
    VerificationMismatch,
    RenameFailed,
}

/// Observable kind of one deterministic mock namespace entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockFileKind {
    Existing,
    Temporary,
    Final,
}

struct MockFile {
    kind: MockFileKind,
    bytes: Vec<u8>,
    synced: bool,
    closed: bool,
}

/// Exact lifecycle events emitted only after the corresponding transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdLifecycleEvent {
    TemporaryCreated(ExportArtifactKind),
    BytesWritten {
        artifact: ExportArtifactKind,
        bytes: usize,
        complete: bool,
    },
    FileSynced(ExportArtifactKind),
    Closed(ExportArtifactKind),
    Reopened(ExportArtifactKind),
    Verified(ExportArtifactKind),
    Renamed(ExportArtifactKind),
}

/// Deterministic in-memory namespace. It makes no real-filesystem claim.
#[derive(Default)]
pub struct MockSdFilesystem {
    files: BTreeMap<String, MockFile>,
    events: Vec<SdLifecycleEvent>,
}

impl MockSdFilesystem {
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
            MockFile {
                kind: MockFileKind::Existing,
                bytes: bytes.to_vec(),
                synced: true,
                closed: true,
            },
        );
        true
    }

    #[must_use]
    pub fn file_bytes(&self, name: &SdFileName) -> Option<&[u8]> {
        self.files
            .get(name.as_str())
            .map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn existing_file_bytes(&self, name: &str) -> Option<&[u8]> {
        self.files.get(name).map(|file| file.bytes.as_slice())
    }

    #[must_use]
    pub fn file_kind(&self, name: &SdFileName) -> Option<MockFileKind> {
        self.files.get(name.as_str()).map(|file| file.kind)
    }

    #[must_use]
    pub fn events(&self) -> &[SdLifecycleEvent] {
        &self.events
    }
}

/// Metadata for one sequentially emitted BBQr frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdBbqrFrame {
    declared_parts: u16,
    part_index: u16,
    frame_len: usize,
}

impl SdBbqrFrame {
    #[must_use]
    pub const fn declared_parts(&self) -> u16 {
        self.declared_parts
    }

    #[must_use]
    pub const fn part_index(&self) -> u16 {
        self.part_index
    }

    #[must_use]
    pub const fn frame_len(&self) -> usize {
        self.frame_len
    }
}

/// Strictly sequential BBQr file-type-P frames for one finalized PSBT.
pub struct SequentialPsbtBbqr<'a> {
    payload: &'a [u8],
    non_final_part_len: usize,
    declared_parts: u16,
    next_part: u16,
}

impl<'a> SequentialPsbtBbqr<'a> {
    fn new(payload: &'a [u8], non_final_part_len: usize) -> Result<Self, BbqrError> {
        let declared_parts = encoded_part_count(payload.len(), non_final_part_len)?;
        Ok(Self {
            payload,
            non_final_part_len,
            declared_parts,
            next_part: 0,
        })
    }

    #[must_use]
    pub const fn declared_parts(&self) -> u16 {
        self.declared_parts
    }

    /// Emit the next frame into the unchanged M22 fixed caller buffer.
    pub fn next_frame(
        &mut self,
        output: &mut [u8; MAX_FRAME_TEXT_BYTES],
    ) -> Result<Option<SdBbqrFrame>, BbqrError> {
        if self.next_part == self.declared_parts {
            return Ok(None);
        }
        let part_index = self.next_part;
        let frame_len = encode_frame(self.payload, self.non_final_part_len, part_index, output)?;
        self.next_part += 1;
        Ok(Some(SdBbqrFrame {
            declared_parts: self.declared_parts,
            part_index,
            frame_len,
        }))
    }
}

fn bind_metadata(
    kind: ExportArtifactKind,
    bytes: &[u8],
    txid: [u8; 32],
    wtxid: [u8; 32],
) -> Result<SdArtifactMetadata, ArtifactBindingError> {
    let digest = sha256(&[bytes]).map_err(|_| ArtifactBindingError::InvalidFinalizedArtifact)?;
    Ok(SdArtifactMetadata {
        kind,
        serialized_len: bytes.len(),
        sha256: digest,
        txid,
        wtxid,
    })
}

fn verify_finalized_pair(
    finalized: &FinalizedTransaction,
    psbt_metadata: SdArtifactMetadata,
    raw_metadata: SdArtifactMetadata,
) -> Result<(), ArtifactBindingError> {
    let view = parse(finalized.finalized_psbt(), InputSource::MicroSd)
        .map_err(|_| ArtifactBindingError::InvalidFinalizedArtifact)?;
    let canonical =
        canonical_serialize(&view).map_err(|_| ArtifactBindingError::AllocationFailed)?;
    if canonical != finalized.finalized_psbt() {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    let stripped = strip_raw_transaction(finalized.raw_transaction())?;
    if stripped != view.unsigned_tx_bytes() {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    if !metadata_matches(psbt_metadata, finalized.finalized_psbt())
        || !metadata_matches(raw_metadata, finalized.raw_transaction())
        || sha256d(&[&stripped]).map_err(|_| ArtifactBindingError::InvalidFinalizedArtifact)?
            != finalized.txid()
        || sha256d(&[finalized.raw_transaction()])
            .map_err(|_| ArtifactBindingError::InvalidFinalizedArtifact)?
            != finalized.wtxid()
    {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    Ok(())
}

fn metadata_matches(metadata: SdArtifactMetadata, bytes: &[u8]) -> bool {
    metadata.serialized_len == bytes.len()
        && matches!(sha256(&[bytes]), Ok(digest) if digest == metadata.sha256)
}

fn names_for(kind: ExportArtifactKind, nonce: ExportNonce) -> SdArtifactNames {
    let suffix = match kind {
        ExportArtifactKind::FinalizedPsbt => PSBT_FINAL_SUFFIX,
        ExportArtifactKind::RawTransaction => RAW_FINAL_SUFFIX,
    };
    let mut final_name = String::with_capacity(3 + NONCE_HEX_BYTES + suffix.len());
    final_name.push_str("qk-");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in nonce.0 {
        final_name.push(char::from(HEX[usize::from(byte >> 4)]));
        final_name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    final_name.push_str(suffix);
    let mut temporary_name = String::with_capacity(final_name.len() + TEMP_SUFFIX.len());
    temporary_name.push_str(&final_name);
    temporary_name.push_str(TEMP_SUFFIX);
    SdArtifactNames {
        final_name: SdFileName(final_name),
        temporary_name: SdFileName(temporary_name),
    }
}

fn preflight(filesystem: &MockSdFilesystem, names: &SdArtifactNames) -> Result<(), SdExportError> {
    if filesystem.files.contains_key(names.final_name.as_str()) {
        return Err(SdExportError::FilenameCollision);
    }
    if filesystem.files.contains_key(names.temporary_name.as_str()) {
        return Err(SdExportError::TemporaryCreateFailed);
    }
    Ok(())
}

fn write_one(
    filesystem: &mut MockSdFilesystem,
    kind: ExportArtifactKind,
    bytes: &[u8],
    metadata: SdArtifactMetadata,
    names: SdArtifactNames,
    fault: Option<SdExportFault>,
) -> Result<SdPublishedArtifact, SdExportError> {
    preflight(filesystem, &names)?;
    if fault == Some(SdExportFault::TemporaryCreateFailed) {
        return Err(SdExportError::TemporaryCreateFailed);
    }
    filesystem.files.insert(
        names.temporary_name.0.clone(),
        MockFile {
            kind: MockFileKind::Temporary,
            bytes: Vec::new(),
            synced: false,
            closed: false,
        },
    );
    filesystem
        .events
        .push(SdLifecycleEvent::TemporaryCreated(kind));

    if fault == Some(SdExportFault::FullMedia) {
        return Err(SdExportError::FullMedia);
    }
    let temporary = filesystem
        .files
        .get_mut(names.temporary_name.as_str())
        .ok_or(SdExportError::TemporaryCreateFailed)?;
    if fault == Some(SdExportFault::WriteFailed) {
        let prefix_len = bytes.len() / 2;
        temporary.bytes.extend_from_slice(&bytes[..prefix_len]);
        filesystem.events.push(SdLifecycleEvent::BytesWritten {
            artifact: kind,
            bytes: prefix_len,
            complete: false,
        });
        return Err(SdExportError::WriteFailed);
    }
    temporary.bytes.extend_from_slice(bytes);
    filesystem.events.push(SdLifecycleEvent::BytesWritten {
        artifact: kind,
        bytes: bytes.len(),
        complete: true,
    });

    if fault == Some(SdExportFault::SyncFailed) {
        return Err(SdExportError::SyncFailed);
    }
    temporary.synced = true;
    filesystem.events.push(SdLifecycleEvent::FileSynced(kind));

    if fault == Some(SdExportFault::CloseFailed) {
        return Err(SdExportError::CloseFailed);
    }
    temporary.closed = true;
    filesystem.events.push(SdLifecycleEvent::Closed(kind));

    if fault == Some(SdExportFault::ReopenFailed) {
        return Err(SdExportError::ReopenFailed);
    }
    filesystem.events.push(SdLifecycleEvent::Reopened(kind));

    if fault == Some(SdExportFault::VerificationMismatch)
        || !verify_readback(kind, &temporary.bytes, metadata)
    {
        return Err(SdExportError::VerificationMismatch);
    }
    filesystem.events.push(SdLifecycleEvent::Verified(kind));

    if fault == Some(SdExportFault::RenameFailed) {
        return Err(SdExportError::RenameFailed);
    }
    if filesystem.files.contains_key(names.final_name.as_str()) {
        return Err(SdExportError::FilenameCollision);
    }
    let mut published = filesystem
        .files
        .remove(names.temporary_name.as_str())
        .ok_or(SdExportError::RenameFailed)?;
    published.kind = MockFileKind::Final;
    filesystem
        .files
        .insert(names.final_name.0.clone(), published);
    filesystem.events.push(SdLifecycleEvent::Renamed(kind));
    Ok(SdPublishedArtifact { metadata, names })
}

fn verify_readback(kind: ExportArtifactKind, bytes: &[u8], metadata: SdArtifactMetadata) -> bool {
    if metadata.kind != kind || !metadata_matches(metadata, bytes) {
        return false;
    }
    match kind {
        ExportArtifactKind::FinalizedPsbt => {
            let Ok(view) = parse(bytes, InputSource::MicroSd) else {
                return false;
            };
            let Ok(canonical) = canonical_serialize(&view) else {
                return false;
            };
            canonical == bytes
                && matches!(sha256d(&[view.unsigned_tx_bytes()]), Ok(txid) if txid == metadata.txid)
        }
        ExportArtifactKind::RawTransaction => {
            let Ok(stripped) = strip_raw_transaction(bytes) else {
                return false;
            };
            matches!(sha256d(&[&stripped]), Ok(txid) if txid == metadata.txid)
                && matches!(sha256d(&[bytes]), Ok(wtxid) if wtxid == metadata.wtxid)
        }
    }
}

struct RawCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RawCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ArtifactBindingError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?;
        self.position = end;
        Ok(value)
    }

    fn compact_size(&mut self) -> Result<(&'a [u8], usize), ArtifactBindingError> {
        let first = *self
            .take(1)?
            .first()
            .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?;
        match first {
            0x00..=0xfc => Ok((
                self.bytes
                    .get(self.position - 1..self.position)
                    .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?,
                usize::from(first),
            )),
            0xfd => {
                let payload = self.take(2)?;
                let value = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
                if value < 0xfd {
                    return Err(ArtifactBindingError::InvalidFinalizedArtifact);
                }
                Ok((
                    self.bytes
                        .get(self.position - 3..self.position)
                        .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?,
                    value,
                ))
            }
            0xfe => {
                let payload = self.take(4)?;
                let value = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                if value <= u32::from(u16::MAX) {
                    return Err(ArtifactBindingError::InvalidFinalizedArtifact);
                }
                Ok((
                    self.bytes
                        .get(self.position - 5..self.position)
                        .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?,
                    usize::try_from(value)
                        .map_err(|_| ArtifactBindingError::InvalidFinalizedArtifact)?,
                ))
            }
            0xff => {
                let payload = self.take(8)?;
                let value = u64::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                if value <= u64::from(u32::MAX) {
                    return Err(ArtifactBindingError::InvalidFinalizedArtifact);
                }
                Ok((
                    self.bytes
                        .get(self.position - 9..self.position)
                        .ok_or(ArtifactBindingError::InvalidFinalizedArtifact)?,
                    usize::try_from(value)
                        .map_err(|_| ArtifactBindingError::InvalidFinalizedArtifact)?,
                ))
            }
        }
    }
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ArtifactBindingError> {
    output
        .try_reserve(bytes.len())
        .map_err(|_| ArtifactBindingError::AllocationFailed)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn strip_raw_transaction(raw: &[u8]) -> Result<Vec<u8>, ArtifactBindingError> {
    let mut cursor = RawCursor::new(raw);
    let mut stripped = Vec::new();
    stripped
        .try_reserve_exact(raw.len())
        .map_err(|_| ArtifactBindingError::AllocationFailed)?;
    append(&mut stripped, cursor.take(4)?)?;
    if cursor.take(2)? != [0x00, 0x01] {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    let (input_count_bytes, input_count) = cursor.compact_size()?;
    if input_count == 0 {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    append(&mut stripped, input_count_bytes)?;
    for _ in 0..input_count {
        append(&mut stripped, cursor.take(36)?)?;
        let (script_len_bytes, script_len) = cursor.compact_size()?;
        if script_len != 0 {
            return Err(ArtifactBindingError::InvalidFinalizedArtifact);
        }
        append(&mut stripped, script_len_bytes)?;
        append(&mut stripped, cursor.take(script_len)?)?;
        append(&mut stripped, cursor.take(4)?)?;
    }
    let (output_count_bytes, output_count) = cursor.compact_size()?;
    if output_count == 0 {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    append(&mut stripped, output_count_bytes)?;
    for _ in 0..output_count {
        append(&mut stripped, cursor.take(8)?)?;
        let (script_len_bytes, script_len) = cursor.compact_size()?;
        append(&mut stripped, script_len_bytes)?;
        append(&mut stripped, cursor.take(script_len)?)?;
    }
    for _ in 0..input_count {
        let (_, item_count) = cursor.compact_size()?;
        if item_count != 4 {
            return Err(ArtifactBindingError::InvalidFinalizedArtifact);
        }
        for item_index in 0..item_count {
            let (_, item_len) = cursor.compact_size()?;
            let item = cursor.take(item_len)?;
            match item_index {
                0 if !item.is_empty() => {
                    return Err(ArtifactBindingError::InvalidFinalizedArtifact)
                }
                1 | 2 if item.is_empty() || item.len() > 72 || item.last() != Some(&1) => {
                    return Err(ArtifactBindingError::InvalidFinalizedArtifact)
                }
                3 if item.len() != 105 => {
                    return Err(ArtifactBindingError::InvalidFinalizedArtifact)
                }
                _ => {}
            }
        }
    }
    append(&mut stripped, cursor.take(4)?)?;
    if cursor.position != raw.len() {
        return Err(ArtifactBindingError::InvalidFinalizedArtifact);
    }
    Ok(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReviewReadyWorkflow;
    use qk_bbqr::{Reassembler, MAX_TOTAL_DECODED_BYTES};
    use qk_descriptor::parse_descriptor_pair;

    const FIXTURE: &str = include_str!("../tests/fixtures/m25_export.txt");
    const NONCE: ExportNonce = ExportNonce::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]);

    fn global(name: &str) -> &str {
        FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .expect("fixture global field")
    }

    fn hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2));
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
            })
            .collect()
    }

    fn hex_32(value: &str) -> [u8; 32] {
        hex(value).try_into().expect("32-byte field")
    }

    fn finalized() -> FinalizedTransaction {
        let descriptor = parse_descriptor_pair(
            global("receive_descriptor").as_bytes(),
            global("change_descriptor").as_bytes(),
        )
        .expect("descriptor fixture");
        let s0 = hex(global("initial_psbt_hex"));
        let mut workflow = ReviewReadyWorkflow::new(descriptor).expect("workflow");
        workflow.intake(&s0, InputSource::MicroSd).expect("intake");
        workflow.wake().expect("wake");
        workflow.begin_validation().expect("begin validation");
        workflow.validate().expect("validate");
        workflow.construct_review().expect("review");

        workflow
            .sign_and_finalize_m24(Vec::new(), &[])
            .expect("M25 threshold-complete fixture")
    }

    fn export(tier: KitTier) -> ExportArtifacts {
        ExportArtifacts::from_finalized(finalized(), tier).expect("bound export")
    }

    fn names(kind: ExportArtifactKind) -> SdArtifactNames {
        names_for(kind, NONCE)
    }

    #[test]
    fn exact_tier_exposure_and_bound_artifact_facts() {
        let expected_psbt = hex(global("finalized_psbt_hex"));
        let expected_raw = hex(global("raw_tx_hex"));
        let expected_txid = hex_32(global("txid_raw_hex"));
        let expected_wtxid = hex_32(global("wtxid_raw_hex"));

        for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
            let owner = export(tier);
            let (psbt, raw) = match owner.artifacts() {
                TierArtifacts::SimpleRecovery {
                    finalized_psbt,
                    raw_transaction,
                }
                | TierArtifacts::Inheritance {
                    finalized_psbt,
                    raw_transaction,
                } => (finalized_psbt, raw_transaction),
                TierArtifacts::QuantumShelter { .. } => panic!("wrong tier exposure"),
            };
            assert_eq!(psbt.bytes(), expected_psbt);
            assert_eq!(raw.bytes(), expected_raw);
            for metadata in [psbt.metadata(), raw.metadata()] {
                assert_eq!(metadata.txid(), expected_txid);
                assert_eq!(metadata.wtxid(), expected_wtxid);
            }
            assert_eq!(psbt.metadata().serialized_len(), expected_psbt.len());
            assert_eq!(raw.metadata().serialized_len(), expected_raw.len());
            assert_eq!(
                psbt.metadata().sha256(),
                hex_32(global("finalized_psbt_sha256"))
            );
            assert_eq!(raw.metadata().sha256(), hex_32(global("raw_tx_sha256")));
        }

        let quantum = export(KitTier::QuantumShelter);
        match quantum.artifacts() {
            TierArtifacts::QuantumShelter { raw_transaction } => {
                assert_eq!(raw_transaction.bytes(), expected_raw)
            }
            _ => panic!("Quantum Shelter exposed a PSBT"),
        }
    }

    #[test]
    fn exact_nonce_names_are_lowercase_and_closed() {
        let psbt = names(ExportArtifactKind::FinalizedPsbt);
        let raw = names(ExportArtifactKind::RawTransaction);
        assert_eq!(
            psbt.final_name().as_str(),
            "qk-000102030405060708090a0b0c0d0e0f-final.psbt"
        );
        assert_eq!(
            psbt.temporary_name().as_str(),
            "qk-000102030405060708090a0b0c0d0e0f-final.psbt.tmp"
        );
        assert_eq!(
            raw.final_name().as_str(),
            "qk-000102030405060708090a0b0c0d0e0f-final.tx"
        );
        assert_eq!(
            raw.temporary_name().as_str(),
            "qk-000102030405060708090a0b0c0d0e0f-final.tx.tmp"
        );
        for name in [
            psbt.final_name(),
            psbt.temporary_name(),
            raw.final_name(),
            raw.temporary_name(),
        ] {
            assert!(name.as_str().bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
            }));
        }
    }

    #[test]
    fn simple_sd_success_is_two_complete_verified_artifacts() {
        let owner = export(KitTier::SimpleRecovery);
        let (finalized_psbt, raw_transaction) = match owner.artifacts() {
            TierArtifacts::SimpleRecovery {
                finalized_psbt,
                raw_transaction,
            } => (finalized_psbt, raw_transaction),
            _ => panic!("tier"),
        };
        let expected_psbt = finalized_psbt.bytes().to_vec();
        let expected_raw = raw_transaction.bytes().to_vec();
        let psbt_names = names(ExportArtifactKind::FinalizedPsbt);
        let raw_names = names(ExportArtifactKind::RawTransaction);
        let mut fs = MockSdFilesystem::new();
        assert!(fs.insert_existing("input.psbt", b"immutable input"));
        let psbt_receipt = finalized_psbt
            .write_mock_sd(NONCE, &mut fs, None)
            .expect("mock SD PSBT");
        let raw_receipt = raw_transaction
            .write_mock_sd(NONCE, &mut fs, None)
            .expect("mock SD raw transaction");
        assert_eq!(psbt_receipt.metadata(), finalized_psbt.metadata());
        assert_eq!(raw_receipt.metadata(), raw_transaction.metadata());
        assert_eq!(
            fs.file_bytes(psbt_names.final_name()),
            Some(expected_psbt.as_slice())
        );
        assert_eq!(
            fs.file_bytes(raw_names.final_name()),
            Some(expected_raw.as_slice())
        );
        assert_eq!(
            fs.file_kind(psbt_names.final_name()),
            Some(MockFileKind::Final)
        );
        assert_eq!(
            fs.file_kind(raw_names.final_name()),
            Some(MockFileKind::Final)
        );
        assert_eq!(fs.file_bytes(psbt_names.temporary_name()), None);
        assert_eq!(fs.file_bytes(raw_names.temporary_name()), None);
        assert_eq!(
            fs.existing_file_bytes("input.psbt"),
            Some(b"immutable input".as_slice())
        );
        assert_eq!(fs.events().len(), 14);
        assert_eq!(
            fs.events().last(),
            Some(&SdLifecycleEvent::Renamed(
                ExportArtifactKind::RawTransaction
            ))
        );
    }

    #[test]
    fn inheritance_uses_two_artifacts_and_quantum_is_sd_raw_only() {
        let inheritance = export(KitTier::Inheritance);
        let mut inheritance_fs = MockSdFilesystem::new();
        let (inheritance_psbt, inheritance_raw) = match inheritance.artifacts() {
            TierArtifacts::Inheritance {
                finalized_psbt,
                raw_transaction,
            } => (finalized_psbt, raw_transaction),
            _ => panic!("tier"),
        };
        inheritance_psbt
            .write_mock_sd(NONCE, &mut inheritance_fs, None)
            .expect("inheritance PSBT");
        inheritance_raw
            .write_mock_sd(NONCE, &mut inheritance_fs, None)
            .expect("inheritance raw");
        assert_eq!(inheritance_fs.events().len(), 14);

        let quantum = export(KitTier::QuantumShelter);
        let mut quantum_fs = MockSdFilesystem::new();
        let quantum_raw = match quantum.artifacts() {
            TierArtifacts::QuantumShelter { raw_transaction } => raw_transaction,
            _ => panic!("tier"),
        };
        quantum_raw
            .write_mock_sd(NONCE, &mut quantum_fs, None)
            .expect("quantum raw");
        assert_eq!(quantum_fs.events().len(), 7);
        assert_eq!(
            quantum_fs.file_bytes(names(ExportArtifactKind::FinalizedPsbt).final_name()),
            None
        );
        assert_eq!(
            quantum_fs.file_bytes(names(ExportArtifactKind::FinalizedPsbt).temporary_name()),
            None
        );
        assert_eq!(
            quantum_fs.file_kind(names(ExportArtifactKind::RawTransaction).final_name()),
            Some(MockFileKind::Final)
        );
    }

    #[test]
    fn all_eight_injected_edges_have_named_temp_only_failures() {
        let cases = [
            (SdExportFault::FullMedia, SdExportError::FullMedia, Some(0)),
            (
                SdExportFault::TemporaryCreateFailed,
                SdExportError::TemporaryCreateFailed,
                None,
            ),
            (
                SdExportFault::WriteFailed,
                SdExportError::WriteFailed,
                Some(1),
            ),
            (
                SdExportFault::SyncFailed,
                SdExportError::SyncFailed,
                Some(2),
            ),
            (
                SdExportFault::CloseFailed,
                SdExportError::CloseFailed,
                Some(2),
            ),
            (
                SdExportFault::ReopenFailed,
                SdExportError::ReopenFailed,
                Some(2),
            ),
            (
                SdExportFault::VerificationMismatch,
                SdExportError::VerificationMismatch,
                Some(2),
            ),
            (
                SdExportFault::RenameFailed,
                SdExportError::RenameFailed,
                Some(2),
            ),
        ];
        for kind in [
            ExportArtifactKind::FinalizedPsbt,
            ExportArtifactKind::RawTransaction,
        ] {
            for (fault, expected, residue_class) in cases {
                let owner = export(KitTier::SimpleRecovery);
                let artifact_len = match owner.artifacts() {
                    TierArtifacts::SimpleRecovery {
                        finalized_psbt,
                        raw_transaction,
                    } => match kind {
                        ExportArtifactKind::FinalizedPsbt => finalized_psbt.bytes().len(),
                        ExportArtifactKind::RawTransaction => raw_transaction.bytes().len(),
                    },
                    _ => panic!("tier"),
                };

                let mut fs = MockSdFilesystem::new();
                assert!(fs.insert_existing("input.psbt", b"input"));
                let result = match owner.artifacts() {
                    TierArtifacts::SimpleRecovery {
                        finalized_psbt,
                        raw_transaction,
                    } => match kind {
                        ExportArtifactKind::FinalizedPsbt => {
                            finalized_psbt.write_mock_sd(NONCE, &mut fs, Some(fault))
                        }
                        ExportArtifactKind::RawTransaction => {
                            raw_transaction.write_mock_sd(NONCE, &mut fs, Some(fault))
                        }
                    },
                    _ => panic!("tier"),
                };
                assert_eq!(result, Err(expected));
                let artifact_names = names(kind);
                assert_eq!(fs.file_bytes(artifact_names.final_name()), None);
                let residue = fs.file_bytes(artifact_names.temporary_name());
                match residue_class {
                    None => assert_eq!(residue, None),
                    Some(0) => assert_eq!(residue.map(<[u8]>::len), Some(0)),
                    Some(1) => assert_eq!(residue.map(<[u8]>::len), Some(artifact_len / 2)),
                    Some(2) => assert_eq!(residue.map(<[u8]>::len), Some(artifact_len)),
                    _ => panic!("closed residue class"),
                }
                assert_eq!(
                    fs.existing_file_bytes("input.psbt"),
                    Some(b"input".as_slice())
                );
            }
        }
    }

    #[test]
    fn filename_collision_is_ninth_error_and_never_overwrites() {
        let errors = [
            SdExportError::FullMedia,
            SdExportError::TemporaryCreateFailed,
            SdExportError::WriteFailed,
            SdExportError::SyncFailed,
            SdExportError::CloseFailed,
            SdExportError::ReopenFailed,
            SdExportError::VerificationMismatch,
            SdExportError::FilenameCollision,
            SdExportError::RenameFailed,
        ];
        assert_eq!(errors.len(), 9);
        let owner = export(KitTier::QuantumShelter);
        let raw = match owner.artifacts() {
            TierArtifacts::QuantumShelter { raw_transaction } => raw_transaction,
            _ => panic!("tier"),
        };
        let raw_names = names(ExportArtifactKind::RawTransaction);
        let mut fs = MockSdFilesystem::new();
        assert!(fs.insert_existing(raw_names.final_name().as_str(), b"collision"));
        assert_eq!(
            raw.write_mock_sd(NONCE, &mut fs, None),
            Err(SdExportError::FilenameCollision)
        );
        assert_eq!(
            fs.file_bytes(raw_names.final_name()),
            Some(b"collision".as_slice())
        );
        assert_eq!(fs.file_bytes(raw_names.temporary_name()), None);
        assert!(fs.events().is_empty());
    }

    #[test]
    fn each_artifact_call_is_atomic_and_bundle_sequencing_is_caller_owned() {
        let owner = export(KitTier::SimpleRecovery);
        let (psbt, raw) = match owner.artifacts() {
            TierArtifacts::SimpleRecovery {
                finalized_psbt,
                raw_transaction,
            } => (finalized_psbt, raw_transaction),
            _ => panic!("tier"),
        };
        let psbt_names = names(ExportArtifactKind::FinalizedPsbt);
        let raw_names = names(ExportArtifactKind::RawTransaction);
        let mut fs = MockSdFilesystem::new();
        psbt.write_mock_sd(NONCE, &mut fs, None)
            .expect("first independent artifact");
        assert_eq!(
            raw.write_mock_sd(NONCE, &mut fs, Some(SdExportFault::RenameFailed)),
            Err(SdExportError::RenameFailed)
        );
        assert_eq!(
            fs.file_kind(psbt_names.final_name()),
            Some(MockFileKind::Final)
        );
        assert_eq!(fs.file_bytes(psbt_names.temporary_name()), None);
        assert_eq!(fs.file_bytes(raw_names.final_name()), None);
        assert_eq!(
            fs.file_kind(raw_names.temporary_name()),
            Some(MockFileKind::Temporary)
        );
    }

    #[test]
    fn retry_reuses_names_and_never_promotes_temp_residue() {
        let owner = export(KitTier::QuantumShelter);
        let raw = match owner.artifacts() {
            TierArtifacts::QuantumShelter { raw_transaction } => raw_transaction,
            _ => panic!("tier"),
        };
        let raw_names = names(ExportArtifactKind::RawTransaction);
        let mut clean_retry = MockSdFilesystem::new();
        assert_eq!(
            raw.write_mock_sd(
                NONCE,
                &mut clean_retry,
                Some(SdExportFault::TemporaryCreateFailed),
            ),
            Err(SdExportError::TemporaryCreateFailed)
        );
        assert!(raw.write_mock_sd(NONCE, &mut clean_retry, None).is_ok());

        let mut residue_retry = MockSdFilesystem::new();
        assert_eq!(
            raw.write_mock_sd(NONCE, &mut residue_retry, Some(SdExportFault::SyncFailed)),
            Err(SdExportError::SyncFailed)
        );
        let residue = residue_retry
            .file_bytes(raw_names.temporary_name())
            .expect("temp residue")
            .to_vec();
        assert_eq!(
            raw.write_mock_sd(NONCE, &mut residue_retry, None),
            Err(SdExportError::TemporaryCreateFailed)
        );
        assert_eq!(
            residue_retry.file_bytes(raw_names.temporary_name()),
            Some(residue.as_slice())
        );
        assert_eq!(residue_retry.file_bytes(raw_names.final_name()), None);
    }

    #[test]
    fn finalized_psbt_frames_sequentially_through_unchanged_bbqr() {
        let owner = export(KitTier::SimpleRecovery);
        let psbt = match owner.artifacts() {
            TierArtifacts::SimpleRecovery { finalized_psbt, .. } => finalized_psbt,
            _ => panic!("tier"),
        };
        let mut encoder = psbt.bbqr(60).expect("explicit M22 geometry");
        let declared = encoder.declared_parts();
        let mut assembled = [0u8; MAX_TOTAL_DECODED_BYTES];
        let mut reassembler = Reassembler::new(&mut assembled);
        let mut frame = [0u8; MAX_FRAME_TEXT_BYTES];
        let mut emitted = 0u16;
        while let Some(metadata) = encoder.next_frame(&mut frame).expect("BBQr frame") {
            assert_eq!(metadata.part_index(), emitted);
            assert_eq!(metadata.declared_parts(), declared);
            assert_eq!(&frame[..4], b"B$2P");
            reassembler
                .submit(&frame[..metadata.frame_len()])
                .expect("M22 reassembly");
            emitted += 1;
        }
        assert_eq!(emitted, declared);
        assert_eq!(reassembler.payload().expect("complete"), psbt.bytes());
        assert!(encoder.next_frame(&mut frame).expect("ended").is_none());
    }
}
