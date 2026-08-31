//! Purpose-bound finalized-artifact ownership and normal-wallet export.
//!
//! The only byte-bearing constructor is crate-private and consumes a view of a
//! verified finalization leaf. Public callers can select one profile-permitted
//! route and drive its exact request/reply sequence; they cannot construct an
//! export from arbitrary bytes.

use crate::error::CoreError;
use crate::io_wire::{
    encode_normal_egress_write, parse_normal_egress_response, ExpectedNormalEgressResponseV2,
    NormalEgressArtifactV2, NormalEgressResponseV2, NormalEgressSinkV2,
};
use crate::wipe::{WipingArray, WipingVec};
use crate::{Operation, INNER_VERSION, MAX_CHUNK_BYTES, MAX_INGRESS_BYTES};
use core::fmt;
use qk_bbqr::{
    encode_typed_frame, encoded_part_count, BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES,
    MAX_TOTAL_DECODED_BYTES,
};
use qk_psbt::FinalizedNormalV3;

/// Exact immutable normal-wallet profile supplied by the supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalProfileV2 {
    SimpleRecovery,
    Inheritance,
    QuantumShelter,
}

impl NormalProfileV2 {
    /// Parse the complete supervisor profile field with no default.
    pub fn parse(bytes: &[u8]) -> Result<Self, NormalArtifactErrorV2> {
        match bytes {
            [] => Err(NormalArtifactErrorV2::ProfileMissing),
            [0x01] => Ok(Self::SimpleRecovery),
            [0x02] => Ok(Self::Inheritance),
            [0x03] => Ok(Self::QuantumShelter),
            [_] => Err(NormalArtifactErrorV2::ProfileUnknown),
            _ => Err(NormalArtifactErrorV2::ProfileMalformed),
        }
    }

    /// Exact export surface this profile exposes after finalization.
    pub const fn route_exposure(self) -> NormalRouteExposureV2 {
        match self {
            Self::SimpleRecovery | Self::Inheritance => NormalRouteExposureV2 {
                sd_finalized_psbt: true,
                sd_raw_transaction: true,
                bbqr_finalized_psbt: true,
                bbqr_raw_transaction: false,
            },
            Self::QuantumShelter => NormalRouteExposureV2 {
                sd_finalized_psbt: false,
                sd_raw_transaction: true,
                bbqr_finalized_psbt: false,
                bbqr_raw_transaction: true,
            },
        }
    }
}

/// Closed artifact surface made visible by one immutable profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalRouteExposureV2 {
    sd_finalized_psbt: bool,
    sd_raw_transaction: bool,
    bbqr_finalized_psbt: bool,
    bbqr_raw_transaction: bool,
}

impl NormalRouteExposureV2 {
    pub const fn sd_finalized_psbt(self) -> bool {
        self.sd_finalized_psbt
    }

    pub const fn sd_raw_transaction(self) -> bool {
        self.sd_raw_transaction
    }

    pub const fn bbqr_finalized_psbt(self) -> bool {
        self.bbqr_finalized_psbt
    }

    pub const fn bbqr_raw_transaction(self) -> bool {
        self.bbqr_raw_transaction
    }
}

/// The one explicit post-finalization export action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalExportActionV2 {
    Sd { caller_nonce: [u8; 16] },
    Bbqr { non_final_part_len: u16 },
}

/// Stable non-secret route fact retained after delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalExportRouteV2 {
    Sd,
    Bbqr,
}

/// Exact finalized artifact kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalArtifactKindV2 {
    FinalizedPsbt,
    RawTransaction,
}

impl NormalArtifactKindV2 {
    const fn wire(self) -> NormalEgressArtifactV2 {
        match self {
            Self::FinalizedPsbt => NormalEgressArtifactV2::FinalizedPsbt,
            Self::RawTransaction => NormalEgressArtifactV2::RawTransaction,
        }
    }

    const fn bbqr_type(self) -> BbqrFileType {
        match self {
            Self::FinalizedPsbt => BbqrFileType::Psbt,
            Self::RawTransaction => BbqrFileType::Transaction,
        }
    }
}

/// Bound public identity facts for one exact finalized byte artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalArtifactFactsV2 {
    kind: NormalArtifactKindV2,
    serialized_len: u32,
    sha256: [u8; 32],
}

impl NormalArtifactFactsV2 {
    pub const fn kind(self) -> NormalArtifactKindV2 {
        self.kind
    }

    pub const fn serialized_len(self) -> u32 {
        self.serialized_len
    }

    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

/// The exact six-byte SD delivery bookkeeping fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalSdReceiptV2 {
    artifact: NormalArtifactKindV2,
    total_len: u32,
}

impl NormalSdReceiptV2 {
    pub const fn artifact(self) -> NormalArtifactKindV2 {
        self.artifact
    }

    pub const fn total_len(self) -> u32 {
        self.total_len
    }
}

/// Stable delivery result. It contains facts only, never artifact bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalExportResultV2 {
    profile: NormalProfileV2,
    route: NormalExportRouteV2,
    finalized_psbt: Option<NormalArtifactFactsV2>,
    raw_transaction: Option<NormalArtifactFactsV2>,
    finalized_psbt_sd_receipt: Option<NormalSdReceiptV2>,
    raw_transaction_sd_receipt: Option<NormalSdReceiptV2>,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl NormalExportResultV2 {
    pub const fn profile(&self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn route(&self) -> NormalExportRouteV2 {
        self.route
    }

    pub const fn finalized_psbt(&self) -> Option<NormalArtifactFactsV2> {
        self.finalized_psbt
    }

    pub const fn raw_transaction(&self) -> Option<NormalArtifactFactsV2> {
        self.raw_transaction
    }

    pub const fn finalized_psbt_sd_receipt(&self) -> Option<NormalSdReceiptV2> {
        self.finalized_psbt_sd_receipt
    }

    pub const fn raw_transaction_sd_receipt(&self) -> Option<NormalSdReceiptV2> {
        self.raw_transaction_sd_receipt
    }

    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }
}

/// Stable progress after one exact broker reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalExportProgressV2 {
    Continue,
    Complete(NormalExportResultV2),
}

/// Closed purpose-bound artifact/export rejection surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalArtifactErrorV2 {
    ProfileMissing,
    ProfileUnknown,
    ProfileMalformed,
    InvalidTransition,
    ExportRouteUnavailable,
    ExportArtifactInvariant,
    ExportReceiptMismatch,
    BbqrVerificationMismatch,
    PartialSdCompletion,
    Finished,
    Core(CoreError),
}

impl NormalArtifactErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProfileMissing => "ProfileMissing",
            Self::ProfileUnknown => "ProfileUnknown",
            Self::ProfileMalformed => "ProfileMalformed",
            Self::InvalidTransition => "InvalidTransition",
            Self::ExportRouteUnavailable => "ExportRouteUnavailable",
            Self::ExportArtifactInvariant => "ExportArtifactInvariant",
            Self::ExportReceiptMismatch => "ExportReceiptMismatch",
            Self::BbqrVerificationMismatch => "BbqrVerificationMismatch",
            Self::PartialSdCompletion => "PartialSdCompletion",
            Self::Finished => "Finished",
            Self::Core(_) => "Core",
        }
    }
}

impl fmt::Display for NormalArtifactErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for NormalArtifactErrorV2 {}

/// Private view constructible only from the finalization leaf in product code.
struct FinalizedArtifactViewV2<'a> {
    finalized_psbt: &'a [u8],
    raw_transaction: &'a [u8],
    finalized_psbt_sha256: [u8; 32],
    raw_sha256: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl<'a> FinalizedArtifactViewV2<'a> {
    fn from_finalized(finalized: &'a FinalizedNormalV3) -> Self {
        Self {
            finalized_psbt: finalized.finalized_psbt(),
            raw_transaction: finalized.raw_transaction(),
            finalized_psbt_sha256: finalized.finalized_psbt_sha256(),
            raw_sha256: finalized.raw_transaction_sha256(),
            txid: finalized.txid(),
            wtxid: finalized.wtxid(),
        }
    }

    #[cfg(test)]
    const fn for_test(
        finalized_psbt: &'a [u8],
        raw_transaction: &'a [u8],
        finalized_psbt_sha256: [u8; 32],
        raw_sha256: [u8; 32],
        txid: [u8; 32],
        wtxid: [u8; 32],
    ) -> Self {
        Self {
            finalized_psbt,
            raw_transaction,
            finalized_psbt_sha256,
            raw_sha256,
            txid,
            wtxid,
        }
    }
}

struct NormalArtifactOwnerV2 {
    facts: NormalArtifactFactsV2,
    bytes: WipingVec,
}

impl NormalArtifactOwnerV2 {
    fn try_copy(
        kind: NormalArtifactKindV2,
        bytes: &[u8],
        sha256: [u8; 32],
    ) -> Result<Self, NormalArtifactErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_INGRESS_BYTES {
            return Err(NormalArtifactErrorV2::ExportArtifactInvariant);
        }
        let serialized_len = u32::try_from(bytes.len())
            .map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
        let mut owner = WipingVec::try_zeroed(bytes.len())
            .map_err(|_| NormalArtifactErrorV2::Core(CoreError::AllocationFailed))?;
        owner.as_mut_slice().copy_from_slice(bytes);
        Ok(Self {
            facts: NormalArtifactFactsV2 {
                kind,
                serialized_len,
                sha256,
            },
            bytes: owner,
        })
    }
}

/// Complete verified finalized bytes before the one explicit route selection.
pub(crate) struct NormalExportArtifactsV2 {
    profile: NormalProfileV2,
    finalized_psbt: NormalArtifactOwnerV2,
    raw_transaction: NormalArtifactOwnerV2,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl NormalExportArtifactsV2 {
    /// Copy only a verified leaf owner into the purpose-bound wipe owners.
    pub(crate) fn bind_finalized(
        profile: NormalProfileV2,
        finalized: &FinalizedNormalV3,
    ) -> Result<Self, NormalArtifactErrorV2> {
        Self::bind_view(profile, FinalizedArtifactViewV2::from_finalized(finalized))
    }

    fn bind_view(
        profile: NormalProfileV2,
        view: FinalizedArtifactViewV2<'_>,
    ) -> Result<Self, NormalArtifactErrorV2> {
        let finalized_psbt = NormalArtifactOwnerV2::try_copy(
            NormalArtifactKindV2::FinalizedPsbt,
            view.finalized_psbt,
            view.finalized_psbt_sha256,
        )?;
        let raw_transaction = NormalArtifactOwnerV2::try_copy(
            NormalArtifactKindV2::RawTransaction,
            view.raw_transaction,
            view.raw_sha256,
        )?;
        Ok(Self {
            profile,
            finalized_psbt,
            raw_transaction,
            txid: view.txid,
            wtxid: view.wtxid,
        })
    }

    pub(crate) fn select(
        self,
        action: NormalExportActionV2,
    ) -> Result<NormalExportTransferV2, NormalArtifactErrorV2> {
        NormalExportTransferV2::select(self, action)
    }
}

/// One owned inner request. Its complete capacity is wiped on drop.
pub struct NormalExportRequestV2 {
    bytes: WipingVec,
}

impl NormalExportRequestV2 {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

#[derive(Clone, Copy)]
enum SelectedRouteV2 {
    Sd { caller_nonce: [u8; 16] },
    Bbqr { non_final_part_len: u16 },
}

impl SelectedRouteV2 {
    const fn sink(self) -> NormalEgressSinkV2 {
        match self {
            Self::Sd { .. } => NormalEgressSinkV2::Sd,
            Self::Bbqr { .. } => NormalEgressSinkV2::Bbqr,
        }
    }

    const fn public(self) -> NormalExportRouteV2 {
        match self {
            Self::Sd { .. } => NormalExportRouteV2::Sd,
            Self::Bbqr { .. } => NormalExportRouteV2::Bbqr,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransferPhaseV2 {
    ReadyBegin,
    AwaitBegin,
    ReadyWrite,
    AwaitWrite { accepted_total: u32 },
    ReadyFinish,
    AwaitFinish,
    Complete,
    Failed,
}

/// One selected no-fallback transfer, owning only its permitted artifact set.
pub(crate) struct NormalExportTransferV2 {
    profile: NormalProfileV2,
    route: SelectedRouteV2,
    current: Option<NormalArtifactOwnerV2>,
    next: Option<NormalArtifactOwnerV2>,
    offset: u32,
    phase: TransferPhaseV2,
    first_sd_final: bool,
    finalized_psbt: Option<NormalArtifactFactsV2>,
    raw_transaction: Option<NormalArtifactFactsV2>,
    finalized_psbt_sd_receipt: Option<NormalSdReceiptV2>,
    raw_transaction_sd_receipt: Option<NormalSdReceiptV2>,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl NormalExportTransferV2 {
    /// Whether one artifact in the logical two-file SD delivery is already
    /// final and therefore any later failure has partial-completion precedence.
    pub(crate) const fn has_partial_sd_completion(&self) -> bool {
        self.first_sd_final
    }

    /// Normalize a failure at the outer QKIP transport boundary through this
    /// transfer's existing one-artifact-finalized invariant, then absorb the
    /// transfer exactly like an inner-response failure.
    pub(crate) fn normalize_outer_error(
        &mut self,
        error: NormalArtifactErrorV2,
    ) -> NormalArtifactErrorV2 {
        self.fail(error)
    }

    fn select(
        artifacts: NormalExportArtifactsV2,
        action: NormalExportActionV2,
    ) -> Result<Self, NormalArtifactErrorV2> {
        let NormalExportArtifactsV2 {
            profile,
            finalized_psbt,
            raw_transaction,
            txid,
            wtxid,
        } = artifacts;
        let route = match action {
            NormalExportActionV2::Sd { caller_nonce } => SelectedRouteV2::Sd { caller_nonce },
            NormalExportActionV2::Bbqr { non_final_part_len } => {
                SelectedRouteV2::Bbqr { non_final_part_len }
            }
        };
        let (current, next, finalized_psbt_facts, raw_transaction_facts) = match (profile, route) {
            (
                NormalProfileV2::SimpleRecovery | NormalProfileV2::Inheritance,
                SelectedRouteV2::Sd { .. },
            ) => {
                let psbt_facts = finalized_psbt.facts;
                let raw_facts = raw_transaction.facts;
                (
                    finalized_psbt,
                    Some(raw_transaction),
                    Some(psbt_facts),
                    Some(raw_facts),
                )
            }
            (
                NormalProfileV2::SimpleRecovery | NormalProfileV2::Inheritance,
                SelectedRouteV2::Bbqr { non_final_part_len },
            ) => {
                validate_bbqr_geometry(&finalized_psbt, non_final_part_len)?;
                let psbt_facts = finalized_psbt.facts;
                drop(raw_transaction);
                (finalized_psbt, None, Some(psbt_facts), None)
            }
            (NormalProfileV2::QuantumShelter, SelectedRouteV2::Sd { .. }) => {
                let raw_facts = raw_transaction.facts;
                drop(finalized_psbt);
                (raw_transaction, None, None, Some(raw_facts))
            }
            (NormalProfileV2::QuantumShelter, SelectedRouteV2::Bbqr { non_final_part_len }) => {
                validate_bbqr_geometry(&raw_transaction, non_final_part_len)?;
                let raw_facts = raw_transaction.facts;
                drop(finalized_psbt);
                (raw_transaction, None, None, Some(raw_facts))
            }
        };
        Ok(Self {
            profile,
            route,
            current: Some(current),
            next,
            offset: 0,
            phase: TransferPhaseV2::ReadyBegin,
            first_sd_final: false,
            finalized_psbt: finalized_psbt_facts,
            raw_transaction: raw_transaction_facts,
            finalized_psbt_sd_receipt: None,
            raw_transaction_sd_receipt: None,
            txid,
            wtxid,
        })
    }

    /// Build the sole next request. Calling again before accepting its reply
    /// terminates this transfer as an invalid transition.
    pub fn next_request(&mut self) -> Result<NormalExportRequestV2, NormalArtifactErrorV2> {
        let request = match self.phase {
            TransferPhaseV2::ReadyBegin => self.build_begin(),
            TransferPhaseV2::ReadyWrite => self.build_write(),
            TransferPhaseV2::ReadyFinish => self.build_finish(),
            TransferPhaseV2::Complete | TransferPhaseV2::Failed => {
                return Err(NormalArtifactErrorV2::Finished)
            }
            TransferPhaseV2::AwaitBegin
            | TransferPhaseV2::AwaitWrite { .. }
            | TransferPhaseV2::AwaitFinish => Err(NormalArtifactErrorV2::InvalidTransition),
        };
        match request {
            Ok(request) => Ok(request),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Consume the complete hostile inner reply for the outstanding request.
    pub fn accept_response(
        &mut self,
        response: &[u8],
    ) -> Result<NormalExportProgressV2, NormalArtifactErrorV2> {
        let result = match self.phase {
            TransferPhaseV2::AwaitBegin => self.accept_begin(response),
            TransferPhaseV2::AwaitWrite { accepted_total } => {
                self.accept_write(response, accepted_total)
            }
            TransferPhaseV2::AwaitFinish => self.accept_finish(response),
            TransferPhaseV2::Complete | TransferPhaseV2::Failed => {
                return Err(NormalArtifactErrorV2::Finished)
            }
            TransferPhaseV2::ReadyBegin
            | TransferPhaseV2::ReadyWrite
            | TransferPhaseV2::ReadyFinish => Err(NormalArtifactErrorV2::InvalidTransition),
        };
        match result {
            Ok(progress) => Ok(progress),
            Err(error) => Err(self.fail(error)),
        }
    }

    fn current(&self) -> Result<&NormalArtifactOwnerV2, NormalArtifactErrorV2> {
        self.current
            .as_ref()
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)
    }

    fn build_begin(&mut self) -> Result<NormalExportRequestV2, NormalArtifactErrorV2> {
        let artifact = self.current()?;
        let request = match (self.route, artifact.facts.kind) {
            (SelectedRouteV2::Sd { caller_nonce }, NormalArtifactKindV2::FinalizedPsbt) => {
                build_sd_begin(
                    NormalEgressArtifactV2::FinalizedPsbt,
                    artifact.facts.serialized_len,
                    &caller_nonce,
                    b"-final.psbt",
                )?
            }
            (SelectedRouteV2::Sd { caller_nonce }, NormalArtifactKindV2::RawTransaction) => {
                build_sd_begin(
                    NormalEgressArtifactV2::RawTransaction,
                    artifact.facts.serialized_len,
                    &caller_nonce,
                    b"-final.tx",
                )?
            }
            (SelectedRouteV2::Bbqr { non_final_part_len }, NormalArtifactKindV2::FinalizedPsbt) => {
                build_bbqr_begin(
                    NormalEgressArtifactV2::FinalizedPsbt,
                    artifact.facts.serialized_len,
                    non_final_part_len,
                )?
            }
            (
                SelectedRouteV2::Bbqr { non_final_part_len },
                NormalArtifactKindV2::RawTransaction,
            ) => build_bbqr_begin(
                NormalEgressArtifactV2::RawTransaction,
                artifact.facts.serialized_len,
                non_final_part_len,
            )?,
        };
        self.phase = TransferPhaseV2::AwaitBegin;
        Ok(NormalExportRequestV2 { bytes: request })
    }

    fn build_write(&mut self) -> Result<NormalExportRequestV2, NormalArtifactErrorV2> {
        let artifact = self.current()?;
        let offset = usize::try_from(self.offset)
            .map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
        let end = offset
            .checked_add(MAX_CHUNK_BYTES)
            .map_or(artifact.bytes.len(), |candidate| {
                candidate.min(artifact.bytes.len())
            });
        let chunk = artifact
            .bytes
            .as_slice()
            .get(offset..end)
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
        let accepted_total =
            u32::try_from(end).map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
        let request_len = 16usize
            .checked_add(chunk.len())
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
        let mut request = WipingVec::try_zeroed(request_len)
            .map_err(|_| NormalArtifactErrorV2::Core(CoreError::AllocationFailed))?;
        if encode_normal_egress_write(self.offset, chunk, request.as_mut_slice())
            != Some(request_len)
        {
            return Err(NormalArtifactErrorV2::ExportArtifactInvariant);
        }
        self.phase = TransferPhaseV2::AwaitWrite { accepted_total };
        Ok(NormalExportRequestV2 { bytes: request })
    }

    fn build_finish(&mut self) -> Result<NormalExportRequestV2, NormalArtifactErrorV2> {
        let request = build_finish_request()?;
        self.phase = TransferPhaseV2::AwaitFinish;
        Ok(NormalExportRequestV2 { bytes: request })
    }

    fn accept_begin(
        &mut self,
        response: &[u8],
    ) -> Result<NormalExportProgressV2, NormalArtifactErrorV2> {
        let artifact = self.current()?.facts.kind.wire();
        let expected = ExpectedNormalEgressResponseV2::Begin {
            sink: self.route.sink(),
            artifact,
        };
        match parse_normal_egress_response(response, expected) {
            Ok(NormalEgressResponseV2::Begin) => {
                self.phase = TransferPhaseV2::ReadyWrite;
                Ok(NormalExportProgressV2::Continue)
            }
            Ok(_) => Err(NormalArtifactErrorV2::ExportReceiptMismatch),
            Err(error) => Err(map_peer_error(error)),
        }
    }

    fn accept_write(
        &mut self,
        response: &[u8],
        accepted_total: u32,
    ) -> Result<NormalExportProgressV2, NormalArtifactErrorV2> {
        let artifact_kind = self.current()?.facts.kind;
        let serialized_len = self.current()?.facts.serialized_len;
        let expected = ExpectedNormalEgressResponseV2::Write {
            sink: self.route.sink(),
            artifact: artifact_kind.wire(),
            accepted_total,
        };
        match parse_normal_egress_response(response, expected) {
            Ok(NormalEgressResponseV2::Write {
                accepted_total: actual,
            }) if actual == accepted_total => {
                self.offset = actual;
                self.phase = if actual == serialized_len {
                    TransferPhaseV2::ReadyFinish
                } else {
                    TransferPhaseV2::ReadyWrite
                };
                Ok(NormalExportProgressV2::Continue)
            }
            Ok(_) => Err(NormalArtifactErrorV2::ExportReceiptMismatch),
            Err(error) => Err(map_peer_error(error)),
        }
    }

    fn accept_finish(
        &mut self,
        response: &[u8],
    ) -> Result<NormalExportProgressV2, NormalArtifactErrorV2> {
        let artifact = self.current()?;
        let artifact_kind = artifact.facts.kind;
        let expected = ExpectedNormalEgressResponseV2::Finish {
            sink: self.route.sink(),
            artifact: artifact_kind.wire(),
            total_len: artifact.facts.serialized_len,
        };
        let parsed = match parse_normal_egress_response(response, expected) {
            Ok(parsed) => parsed,
            Err(CoreError::IoRejected(error)) => {
                return Err(NormalArtifactErrorV2::Core(CoreError::IoRejected(error)))
            }
            Err(_) if matches!(self.route, SelectedRouteV2::Bbqr { .. }) => {
                return Err(NormalArtifactErrorV2::BbqrVerificationMismatch)
            }
            Err(_) => return Err(NormalArtifactErrorV2::ExportReceiptMismatch),
        };
        match (self.route, parsed) {
            (SelectedRouteV2::Sd { .. }, NormalEgressResponseV2::SdFinish) => {
                let receipt = NormalSdReceiptV2 {
                    artifact: artifact_kind,
                    total_len: artifact.facts.serialized_len,
                };
                match artifact_kind {
                    NormalArtifactKindV2::FinalizedPsbt => {
                        self.finalized_psbt_sd_receipt = Some(receipt)
                    }
                    NormalArtifactKindV2::RawTransaction => {
                        self.raw_transaction_sd_receipt = Some(receipt)
                    }
                }
            }
            (
                SelectedRouteV2::Bbqr { non_final_part_len },
                NormalEgressResponseV2::BbqrFinish {
                    frame_count,
                    encoded_frames,
                },
            ) => verify_bbqr_batch(artifact, non_final_part_len, frame_count, encoded_frames)?,
            _ => return Err(NormalArtifactErrorV2::ExportReceiptMismatch),
        }

        drop(self.current.take());
        if let Some(next) = self.next.take() {
            self.first_sd_final = true;
            self.current = Some(next);
            self.offset = 0;
            self.phase = TransferPhaseV2::ReadyBegin;
            return Ok(NormalExportProgressV2::Continue);
        }
        self.phase = TransferPhaseV2::Complete;
        Ok(NormalExportProgressV2::Complete(self.result()))
    }

    const fn result(&self) -> NormalExportResultV2 {
        NormalExportResultV2 {
            profile: self.profile,
            route: self.route.public(),
            finalized_psbt: self.finalized_psbt,
            raw_transaction: self.raw_transaction,
            finalized_psbt_sd_receipt: self.finalized_psbt_sd_receipt,
            raw_transaction_sd_receipt: self.raw_transaction_sd_receipt,
            txid: self.txid,
            wtxid: self.wtxid,
        }
    }

    fn fail(&mut self, error: NormalArtifactErrorV2) -> NormalArtifactErrorV2 {
        let mapped = if self.first_sd_final {
            NormalArtifactErrorV2::PartialSdCompletion
        } else {
            error
        };
        self.phase = TransferPhaseV2::Failed;
        drop(self.current.take());
        drop(self.next.take());
        mapped
    }
}

impl Drop for NormalExportTransferV2 {
    fn drop(&mut self) {
        crate::wipe::bytes(&mut self.txid);
        crate::wipe::bytes(&mut self.wtxid);
    }
}

fn validate_bbqr_geometry(
    artifact: &NormalArtifactOwnerV2,
    non_final_part_len: u16,
) -> Result<(), NormalArtifactErrorV2> {
    encoded_part_count(artifact.bytes.len(), usize::from(non_final_part_len))
        .map(|_| ())
        .map_err(|_| NormalArtifactErrorV2::ExportRouteUnavailable)
}

fn verify_bbqr_batch(
    artifact: &NormalArtifactOwnerV2,
    non_final_part_len: u16,
    frame_count: u16,
    encoded_frames: &[u8],
) -> Result<(), NormalArtifactErrorV2> {
    let expected_count = encoded_part_count(artifact.bytes.len(), usize::from(non_final_part_len))
        .map_err(|_| NormalArtifactErrorV2::BbqrVerificationMismatch)?;
    if frame_count != expected_count {
        return Err(NormalArtifactErrorV2::BbqrVerificationMismatch);
    }
    let mut output = WipingVec::try_zeroed(MAX_TOTAL_DECODED_BYTES)
        .map_err(|_| NormalArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    let fixed: &mut [u8; MAX_TOTAL_DECODED_BYTES] = output
        .as_mut_slice()
        .try_into()
        .map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let mut reassembler = Reassembler::new_typed(artifact.facts.kind.bbqr_type(), fixed);
    let mut cursor = 0usize;
    for submitted in 0..frame_count {
        let length_end = cursor
            .checked_add(2)
            .ok_or(NormalArtifactErrorV2::BbqrVerificationMismatch)?;
        let length_bytes: &[u8; 2] = encoded_frames
            .get(cursor..length_end)
            .ok_or(NormalArtifactErrorV2::BbqrVerificationMismatch)?
            .try_into()
            .map_err(|_| NormalArtifactErrorV2::BbqrVerificationMismatch)?;
        let frame_len = usize::from(u16::from_le_bytes(*length_bytes));
        let frame_end = length_end
            .checked_add(frame_len)
            .ok_or(NormalArtifactErrorV2::BbqrVerificationMismatch)?;
        let frame = encoded_frames
            .get(length_end..frame_end)
            .ok_or(NormalArtifactErrorV2::BbqrVerificationMismatch)?;
        let mut expected_frame = WipingArray::<MAX_FRAME_TEXT_BYTES>::zeroed();
        let expected_len = match encode_typed_frame(
            artifact.facts.kind.bbqr_type(),
            artifact.bytes.as_slice(),
            usize::from(non_final_part_len),
            submitted,
            expected_frame.as_mut_array(),
        ) {
            Ok(length) => length,
            Err(_) => return Err(NormalArtifactErrorV2::BbqrVerificationMismatch),
        };
        let frame_matches = expected_len == frame.len()
            && expected_frame.as_array().get(..expected_len) == Some(frame);
        if !frame_matches {
            return Err(NormalArtifactErrorV2::BbqrVerificationMismatch);
        }
        let progress = reassembler
            .submit(frame)
            .map_err(|_| NormalArtifactErrorV2::BbqrVerificationMismatch)?;
        if progress.declared_parts != frame_count
            || progress.received_parts != submitted.saturating_add(1)
            || progress.was_duplicate
            || progress.complete != (submitted.saturating_add(1) == frame_count)
        {
            return Err(NormalArtifactErrorV2::BbqrVerificationMismatch);
        }
        cursor = frame_end;
    }
    if cursor != encoded_frames.len()
        || reassembler
            .payload()
            .map_err(|_| NormalArtifactErrorV2::BbqrVerificationMismatch)?
            != artifact.bytes.as_slice()
    {
        return Err(NormalArtifactErrorV2::BbqrVerificationMismatch);
    }
    Ok(())
}

fn build_sd_begin(
    artifact: NormalEgressArtifactV2,
    total_len: u32,
    caller_nonce: &[u8; 16],
    suffix: &[u8],
) -> Result<WipingVec, NormalArtifactErrorV2> {
    let filename_len = 35usize
        .checked_add(suffix.len())
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let body_len = 9usize
        .checked_add(filename_len)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let complete_len = 8usize
        .checked_add(body_len)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let mut output = WipingVec::try_zeroed(complete_len)
        .map_err(|_| NormalArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    let body_len_u32 =
        u32::try_from(body_len).map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let aux_len_u16 = u16::try_from(
        filename_len
            .checked_add(1)
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?,
    )
    .map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let filename_len_u8 =
        u8::try_from(filename_len).map_err(|_| NormalArtifactErrorV2::ExportArtifactInvariant)?;
    let [body_0, body_1, body_2, body_3] = body_len_u32.to_le_bytes();
    let bytes = output.as_mut_slice();
    bytes
        .get_mut(..8)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&[
            INNER_VERSION,
            Operation::EgressBegin.wire_value(),
            0,
            0,
            body_0,
            body_1,
            body_2,
            body_3,
        ]);
    bytes
        .get_mut(8..10)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&[NormalEgressSinkV2::Sd.wire_value(), artifact.wire_value()]);
    bytes
        .get_mut(10..14)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&total_len.to_le_bytes());
    bytes
        .get_mut(14..16)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&aux_len_u16.to_le_bytes());
    *bytes
        .get_mut(16)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)? = filename_len_u8;
    bytes
        .get_mut(17..20)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(b"qk-");
    for (index, byte) in caller_nonce.iter().copied().enumerate() {
        let start = index
            .checked_mul(2)
            .and_then(|value| value.checked_add(20))
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
        let end = start
            .checked_add(2)
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?;
        bytes
            .get_mut(start..end)
            .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
            .copy_from_slice(&[lower_hex(byte >> 4), lower_hex(byte & 0x0f)]);
    }
    bytes
        .get_mut(52..)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(suffix);
    Ok(output)
}

fn build_bbqr_begin(
    artifact: NormalEgressArtifactV2,
    total_len: u32,
    non_final_part_len: u16,
) -> Result<WipingVec, NormalArtifactErrorV2> {
    let mut output = WipingVec::try_zeroed(18)
        .map_err(|_| NormalArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    let bytes = output.as_mut_slice();
    bytes
        .get_mut(..10)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&[
            INNER_VERSION,
            Operation::EgressBegin.wire_value(),
            0,
            0,
            10,
            0,
            0,
            0,
            NormalEgressSinkV2::Bbqr.wire_value(),
            artifact.wire_value(),
        ]);
    bytes
        .get_mut(10..14)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&total_len.to_le_bytes());
    bytes
        .get_mut(14..16)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&2u16.to_le_bytes());
    bytes
        .get_mut(16..18)
        .ok_or(NormalArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&non_final_part_len.to_le_bytes());
    Ok(output)
}

fn build_finish_request() -> Result<WipingVec, NormalArtifactErrorV2> {
    let mut output = WipingVec::try_zeroed(8)
        .map_err(|_| NormalArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    output.as_mut_slice().copy_from_slice(&[
        INNER_VERSION,
        Operation::EgressFinish.wire_value(),
        0,
        0,
        0,
        0,
        0,
        0,
    ]);
    Ok(output)
}

const fn lower_hex(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0'.wrapping_add(nibble)
    } else {
        b'a'.wrapping_add(nibble.wrapping_sub(10))
    }
}

fn map_peer_error(error: CoreError) -> NormalArtifactErrorV2 {
    match error {
        CoreError::IoRejected(rejection) => {
            NormalArtifactErrorV2::Core(CoreError::IoRejected(rejection))
        }
        _ => NormalArtifactErrorV2::ExportReceiptMismatch,
    }
}

const _: () = assert!(MAX_TOTAL_DECODED_BYTES == MAX_CHUNK_BYTES);

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::{Operation, INNER_VERSION};
    use qk_bbqr::{encode_typed_frame, encoded_part_count, MAX_FRAME_TEXT_BYTES};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn view<'a>(psbt: &'a [u8], raw: &'a [u8]) -> FinalizedArtifactViewV2<'a> {
        FinalizedArtifactViewV2::for_test(psbt, raw, [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32])
    }

    fn response(opcode: Operation, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![INNER_VERSION, opcode.wire_value(), 0, 0];
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn advance_success(transfer: &mut NormalExportTransferV2) -> NormalExportProgressV2 {
        let request = transfer.next_request().unwrap();
        let operation = request.bytes()[1];
        let body = match operation {
            3 => Vec::new(),
            4 => request.bytes()[12..16].to_vec(),
            5 => {
                let artifact = transfer.current().unwrap();
                match transfer.route {
                    SelectedRouteV2::Sd { .. } => {
                        let mut body = vec![1, artifact.facts.kind.wire().wire_value()];
                        body.extend_from_slice(&artifact.facts.serialized_len.to_le_bytes());
                        body
                    }
                    SelectedRouteV2::Bbqr { non_final_part_len } => {
                        bbqr_body(artifact, non_final_part_len)
                    }
                }
            }
            _ => panic!("unexpected operation"),
        };
        let opcode = match operation {
            3 => Operation::EgressBegin,
            4 => Operation::EgressWrite,
            5 => Operation::EgressFinish,
            _ => panic!("unexpected operation"),
        };
        transfer.accept_response(&response(opcode, &body)).unwrap()
    }

    fn bbqr_body(artifact: &NormalArtifactOwnerV2, part_len: u16) -> Vec<u8> {
        let count = encoded_part_count(artifact.bytes.len(), usize::from(part_len)).unwrap();
        let mut body = vec![2, artifact.facts.kind.wire().wire_value()];
        body.extend_from_slice(&artifact.facts.serialized_len.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        for index in 0..count {
            let mut frame = [0u8; MAX_FRAME_TEXT_BYTES];
            let length = encode_typed_frame(
                artifact.facts.kind.bbqr_type(),
                artifact.bytes.as_slice(),
                usize::from(part_len),
                index,
                &mut frame,
            )
            .unwrap();
            body.extend_from_slice(&(length as u16).to_le_bytes());
            body.extend_from_slice(&frame[..length]);
        }
        body
    }

    #[test]
    fn profile_field_is_exact_and_routes_only_narrow() {
        assert_eq!(
            NormalProfileV2::parse(&[]),
            Err(NormalArtifactErrorV2::ProfileMissing)
        );
        assert_eq!(
            NormalProfileV2::parse(&[0]),
            Err(NormalArtifactErrorV2::ProfileUnknown)
        );
        assert_eq!(
            NormalProfileV2::parse(&[1, 2]),
            Err(NormalArtifactErrorV2::ProfileMalformed)
        );
        assert_eq!(
            NormalProfileV2::parse(&[1]),
            Ok(NormalProfileV2::SimpleRecovery)
        );
        assert_eq!(
            NormalProfileV2::parse(&[2]),
            Ok(NormalProfileV2::Inheritance)
        );
        assert_eq!(
            NormalProfileV2::parse(&[3]),
            Ok(NormalProfileV2::QuantumShelter)
        );

        let simple = NormalProfileV2::SimpleRecovery.route_exposure();
        assert!(simple.sd_finalized_psbt());
        assert!(simple.sd_raw_transaction());
        assert!(simple.bbqr_finalized_psbt());
        assert!(!simple.bbqr_raw_transaction());
        let quantum = NormalProfileV2::QuantumShelter.route_exposure();
        assert!(!quantum.sd_finalized_psbt());
        assert!(quantum.sd_raw_transaction());
        assert!(!quantum.bbqr_finalized_psbt());
        assert!(quantum.bbqr_raw_transaction());
    }

    #[test]
    fn begin_finish_filename_and_geometry_scratch_are_raii_wiped() {
        let begin = build_sd_begin(
            NormalEgressArtifactV2::FinalizedPsbt,
            37,
            &[0xab; 16],
            b"-final.psbt",
        )
        .unwrap();
        assert!(begin.as_slice().windows(3).any(|window| window == b"qk-"));
        let begin_bytes = begin.allocation_bytes();
        reset_wiped_bytes();
        drop(begin);
        assert_eq!(wiped_bytes(), begin_bytes);

        let finish_probe = build_finish_request().unwrap();
        let finish_bytes = finish_probe.allocation_bytes();
        drop(finish_probe);
        reset_wiped_bytes();
        let finish_unwind = catch_unwind(AssertUnwindSafe(|| {
            let request = build_finish_request().unwrap();
            assert_eq!(request.allocation_bytes(), finish_bytes);
            panic!("caught finish-request unwind");
        }));
        assert!(finish_unwind.is_err());
        assert_eq!(wiped_bytes(), finish_bytes);

        reset_wiped_bytes();
        let geometry_unwind = catch_unwind(AssertUnwindSafe(|| {
            let mut expected = WipingArray::<MAX_FRAME_TEXT_BYTES>::zeroed();
            encode_typed_frame(
                BbqrFileType::Transaction,
                &[0x81; 61],
                25,
                0,
                expected.as_mut_array(),
            )
            .unwrap();
            panic!("caught geometry-scratch unwind");
        }));
        assert!(geometry_unwind.is_err());
        assert_eq!(wiped_bytes(), MAX_FRAME_TEXT_BYTES);
    }

    #[test]
    fn sd_bundle_is_ordered_and_only_completes_after_both_receipts() {
        let artifacts = NormalExportArtifactsV2::bind_view(
            NormalProfileV2::SimpleRecovery,
            view(&[0x70; 37], &[0x80; 23]),
        )
        .unwrap();
        let mut transfer = artifacts
            .select(NormalExportActionV2::Sd {
                caller_nonce: [0xab; 16],
            })
            .unwrap();
        let request = transfer.next_request().unwrap();
        let mut expected = vec![1, 3, 0, 0, 55, 0, 0, 0, 1, 1, 37, 0, 0, 0, 47, 0, 46];
        expected.extend_from_slice(b"qk-abababababababababababababababab-final.psbt");
        assert_eq!(request.bytes(), expected);
        drop(request);
        assert_eq!(transfer.phase, TransferPhaseV2::AwaitBegin);
        transfer
            .accept_response(&response(Operation::EgressBegin, &[]))
            .unwrap();
        assert!(matches!(
            advance_success(&mut transfer),
            NormalExportProgressV2::Continue
        ));
        assert!(matches!(
            advance_success(&mut transfer),
            NormalExportProgressV2::Continue
        ));
        assert_eq!(
            transfer.current().unwrap().facts.kind,
            NormalArtifactKindV2::RawTransaction
        );
        let request = transfer.next_request().unwrap();
        let mut expected = vec![1, 3, 0, 0, 53, 0, 0, 0, 1, 2, 23, 0, 0, 0, 45, 0, 44];
        expected.extend_from_slice(b"qk-abababababababababababababababab-final.tx");
        assert_eq!(request.bytes(), expected);
        drop(request);
        transfer
            .accept_response(&response(Operation::EgressBegin, &[]))
            .unwrap();
        assert!(matches!(
            advance_success(&mut transfer),
            NormalExportProgressV2::Continue
        ));
        let completed = advance_success(&mut transfer);
        let NormalExportProgressV2::Complete(result) = completed else {
            panic!("bundle did not complete");
        };
        assert_eq!(result.route(), NormalExportRouteV2::Sd);
        assert_eq!(result.finalized_psbt().unwrap().serialized_len(), 37);
        assert_eq!(result.raw_transaction().unwrap().serialized_len(), 23);
        let psbt_receipt = result.finalized_psbt_sd_receipt().unwrap();
        assert_eq!(psbt_receipt.artifact(), NormalArtifactKindV2::FinalizedPsbt);
        assert_eq!(psbt_receipt.total_len(), 37);
        let transaction_receipt = result.raw_transaction_sd_receipt().unwrap();
        assert_eq!(
            transaction_receipt.artifact(),
            NormalArtifactKindV2::RawTransaction
        );
        assert_eq!(transaction_receipt.total_len(), 23);
    }

    #[test]
    fn second_sd_failure_is_named_partial_completion_and_absorbing() {
        let artifacts = NormalExportArtifactsV2::bind_view(
            NormalProfileV2::Inheritance,
            view(&[0x70; 7], &[0x80; 9]),
        )
        .unwrap();
        let mut transfer = artifacts
            .select(NormalExportActionV2::Sd {
                caller_nonce: [0x01; 16],
            })
            .unwrap();
        for _ in 0..3 {
            assert!(matches!(
                advance_success(&mut transfer),
                NormalExportProgressV2::Continue
            ));
        }
        let _request = transfer.next_request().unwrap();
        assert_eq!(
            transfer.accept_response(&[0]),
            Err(NormalArtifactErrorV2::PartialSdCompletion)
        );
        assert!(matches!(
            transfer.next_request(),
            Err(NormalArtifactErrorV2::Finished)
        ));
    }

    #[test]
    fn bbqr_p_and_t_receipts_are_reassembled_and_compared() {
        let cases = [
            NormalProfileV2::SimpleRecovery,
            NormalProfileV2::QuantumShelter,
        ];
        for profile in cases {
            let artifacts =
                NormalExportArtifactsV2::bind_view(profile, view(&[0x71; 43], &[0x81; 61]))
                    .unwrap();
            let mut transfer = artifacts
                .select(NormalExportActionV2::Bbqr {
                    non_final_part_len: 10,
                })
                .unwrap();
            let request = transfer.next_request().unwrap();
            let (artifact, total_len) = if profile == NormalProfileV2::QuantumShelter {
                (2, 61)
            } else {
                (1, 43)
            };
            assert_eq!(
                request.bytes(),
                &[1, 3, 0, 0, 10, 0, 0, 0, 2, artifact, total_len, 0, 0, 0, 2, 0, 10, 0]
            );
            drop(request);
            transfer
                .accept_response(&response(Operation::EgressBegin, &[]))
                .unwrap();
            assert!(matches!(
                advance_success(&mut transfer),
                NormalExportProgressV2::Continue
            ));
            let completed = advance_success(&mut transfer);
            let NormalExportProgressV2::Complete(result) = completed else {
                panic!("BBQr did not complete");
            };
            assert_eq!(result.route(), NormalExportRouteV2::Bbqr);
            assert_eq!(
                result.finalized_psbt().is_some(),
                profile != NormalProfileV2::QuantumShelter
            );
            assert_eq!(
                result.raw_transaction().is_some(),
                profile == NormalProfileV2::QuantumShelter
            );
        }
    }

    #[test]
    fn hostile_bbqr_reply_mutation_never_becomes_delivery() {
        let artifacts = NormalExportArtifactsV2::bind_view(
            NormalProfileV2::QuantumShelter,
            view(&[0x71; 43], &[0x81; 61]),
        )
        .unwrap();
        let mut transfer = artifacts
            .select(NormalExportActionV2::Bbqr {
                non_final_part_len: 10,
            })
            .unwrap();
        advance_success(&mut transfer);
        advance_success(&mut transfer);
        let request = transfer.next_request().unwrap();
        assert_eq!(request.bytes()[1], Operation::EgressFinish.wire_value());
        let artifact = transfer.current().unwrap();
        let mut body = bbqr_body(artifact, 10);
        let final_byte = body.last_mut().unwrap();
        *final_byte = if *final_byte == b'A' { b'B' } else { b'A' };
        assert_eq!(
            transfer.accept_response(&response(Operation::EgressFinish, &body)),
            Err(NormalArtifactErrorV2::BbqrVerificationMismatch)
        );
        assert!(matches!(
            transfer.next_request(),
            Err(NormalArtifactErrorV2::Finished)
        ));
    }

    #[test]
    fn same_payload_with_different_bbqr_geometry_is_rejected() {
        let artifacts = NormalExportArtifactsV2::bind_view(
            NormalProfileV2::QuantumShelter,
            view(&[0x71; 43], &[0x81; 61]),
        )
        .unwrap();
        let mut transfer = artifacts
            .select(NormalExportActionV2::Bbqr {
                non_final_part_len: 25,
            })
            .unwrap();
        advance_success(&mut transfer);
        advance_success(&mut transfer);
        let request = transfer.next_request().unwrap();
        assert_eq!(request.bytes()[1], Operation::EgressFinish.wire_value());
        let body = bbqr_body(transfer.current().unwrap(), 30);
        assert_eq!(
            transfer.accept_response(&response(Operation::EgressFinish, &body)),
            Err(NormalArtifactErrorV2::BbqrVerificationMismatch)
        );
    }
}
