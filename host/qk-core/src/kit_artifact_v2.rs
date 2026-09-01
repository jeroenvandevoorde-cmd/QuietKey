//! Raw-transaction-only export ownership for QK-DEC-151 Kit-Spend.
//!
//! Only a freshly verified finalization leaf can construct these owners. The
//! finalized PSBT is never copied into this module and no constructor for it
//! exists. One explicit SD or BBQr-T route consumes the artifact.

use crate::error::CoreError;
use crate::io_wire::{
    encode_normal_egress_write, parse_normal_egress_response, ExpectedNormalEgressResponseV2,
    NormalEgressArtifactV2, NormalEgressResponseV2, NormalEgressSinkV2,
};
use crate::normal_artifact_v2::NormalProfileV2;
use crate::wipe::{WipingArray, WipingVec};
use crate::{
    CoreMode, CoreOutbound, CoreSession, Interruption, Operation, INNER_VERSION, MAX_CHUNK_BYTES,
    MAX_INGRESS_BYTES,
};
use core::fmt;
use qk_bbqr::{
    encode_typed_frame, encoded_part_count, BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES,
    MAX_TOTAL_DECODED_BYTES,
};
use qk_psbt::FinalizedNormalV3;

/// The sole post-finalization Kit-Spend delivery choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitExportActionV2 {
    Sd { caller_nonce: [u8; 16] },
    Bbqr { non_final_part_len: u16 },
}

/// Stable non-secret carrier fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitExportRouteV2 {
    Sd,
    Bbqr,
}

/// Bound identity of the sole raw transaction artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitRawTransactionFactsV2 {
    serialized_len: u32,
    sha256: [u8; 32],
}

impl KitRawTransactionFactsV2 {
    pub const fn serialized_len(self) -> u32 {
        self.serialized_len
    }

    pub const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

/// The exact six-byte SD bookkeeping fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitSdReceiptV2 {
    total_len: u32,
}

impl KitSdReceiptV2 {
    pub const fn total_len(self) -> u32 {
        self.total_len
    }
}

/// Stable result facts after one successful carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitExportResultV2 {
    profile: NormalProfileV2,
    route: KitExportRouteV2,
    raw_transaction: KitRawTransactionFactsV2,
    sd_receipt: Option<KitSdReceiptV2>,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl KitExportResultV2 {
    pub const fn profile(&self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn route(&self) -> KitExportRouteV2 {
        self.route
    }

    pub const fn raw_transaction(&self) -> KitRawTransactionFactsV2 {
        self.raw_transaction
    }

    pub const fn sd_receipt(&self) -> Option<KitSdReceiptV2> {
        self.sd_receipt
    }

    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KitExportProgressV2 {
    Continue,
    Complete(KitExportResultV2),
}

/// Closed raw-only export rejection surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitArtifactErrorV2 {
    InvalidTransition,
    ExportRouteUnavailable,
    ExportArtifactInvariant,
    ExportReceiptMismatch,
    BbqrVerificationMismatch,
    Finished,
    Core(CoreError),
}

impl KitArtifactErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidTransition => "InvalidTransition",
            Self::ExportRouteUnavailable => "ExportRouteUnavailable",
            Self::ExportArtifactInvariant => "ExportArtifactInvariant",
            Self::ExportReceiptMismatch => "ExportReceiptMismatch",
            Self::BbqrVerificationMismatch => "BbqrVerificationMismatch",
            Self::Finished => "Finished",
            Self::Core(_) => "Core",
        }
    }
}

impl fmt::Display for KitArtifactErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitArtifactErrorV2 {}

struct RawOwnerV2 {
    facts: KitRawTransactionFactsV2,
    bytes: WipingVec,
}

/// Verified finalization facts before the single carrier choice.
pub(crate) struct KitExportArtifactsV2 {
    profile: NormalProfileV2,
    raw: RawOwnerV2,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl KitExportArtifactsV2 {
    pub(crate) fn bind_finalized(
        profile: NormalProfileV2,
        finalized: &FinalizedNormalV3,
    ) -> Result<Self, KitArtifactErrorV2> {
        let bytes = finalized.raw_transaction();
        if bytes.is_empty() || bytes.len() > MAX_INGRESS_BYTES {
            return Err(KitArtifactErrorV2::ExportArtifactInvariant);
        }
        let serialized_len =
            u32::try_from(bytes.len()).map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
        let mut owned = WipingVec::try_zeroed(bytes.len())
            .map_err(|_| KitArtifactErrorV2::Core(CoreError::AllocationFailed))?;
        owned.as_mut_slice().copy_from_slice(bytes);
        Ok(Self {
            profile,
            raw: RawOwnerV2 {
                facts: KitRawTransactionFactsV2 {
                    serialized_len,
                    sha256: finalized.raw_transaction_sha256(),
                },
                bytes: owned,
            },
            txid: finalized.txid(),
            wtxid: finalized.wtxid(),
        })
    }

    pub(crate) fn select(
        self,
        action: KitExportActionV2,
    ) -> Result<KitExportTransferV2, KitArtifactErrorV2> {
        KitExportTransferV2::select(self, action)
    }
}

/// One owned exact inner qk-io request.
pub(crate) struct KitExportRequestV2 {
    bytes: WipingVec,
}

impl KitExportRequestV2 {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Stream consumption plus either the next complete QKIP request or the
/// completed non-secret delivery facts. Inner qk-io bytes never escape.
pub struct KitDeliveryReceiveOutcomeV2 {
    consumed: usize,
    outbound: Option<CoreOutbound>,
    result: Option<KitExportResultV2>,
}

impl KitDeliveryReceiveOutcomeV2 {
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    pub const fn outbound(&self) -> Option<&CoreOutbound> {
        self.outbound.as_ref()
    }

    pub fn into_outbound(self) -> Option<CoreOutbound> {
        self.outbound
    }

    pub const fn result(&self) -> Option<KitExportResultV2> {
        self.result
    }
}

/// One purpose-bound raw-transaction delivery owner.
///
/// Construction consumes both the finalized Kit-Spend outcome and an already
/// opened Kit-mode process shell. The only byte-bearing public values this
/// owner releases are complete QKIP requests.
pub struct KitDeliverySessionV2 {
    core: CoreSession,
    transfer: Option<KitExportTransferV2>,
    result: Option<KitExportResultV2>,
    failed: bool,
}

impl KitDeliverySessionV2 {
    /// Bind one immutable route and emit its first complete QKIP request.
    pub fn begin(
        outcome: crate::kit_spend_v2::KitSpendOutcomeV2,
        mut core: CoreSession,
        action: KitExportActionV2,
    ) -> Result<(Self, CoreOutbound), KitArtifactErrorV2> {
        if core.mode() != CoreMode::Kit {
            core.terminate_kit(Interruption::OperationFailed);
            return Err(KitArtifactErrorV2::Core(CoreError::InvalidTransition));
        }
        let artifacts = match outcome.into_export_artifacts() {
            Ok(value) => value,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        let mut transfer = match artifacts.select(action) {
            Ok(value) => value,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        let request = match transfer.next_request() {
            Ok(value) => value,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        let outbound = match core.begin_kit_egress(request.bytes()) {
            Ok(value) => value,
            Err(error) => {
                let error = transfer.normalize_outer_error(KitArtifactErrorV2::Core(error));
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        drop(request);
        Ok((
            Self {
                core,
                transfer: Some(transfer),
                result: None,
                failed: false,
            },
            outbound,
        ))
    }

    /// Consume at most one hostile QKIP stream prefix and automatically emit
    /// the next exact request until the selected route completes.
    pub fn receive(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<KitDeliveryReceiveOutcomeV2, KitArtifactErrorV2> {
        if self.failed || self.result.is_some() || self.transfer.is_none() {
            return Err(KitArtifactErrorV2::Finished);
        }
        let outer = match self.core.receive_kit_egress(input, ancillary_present) {
            Ok(value) => value,
            Err(error) => return Err(self.fail(KitArtifactErrorV2::Core(error))),
        };
        if !outer.response_ready {
            return Ok(KitDeliveryReceiveOutcomeV2 {
                consumed: outer.consumed,
                outbound: None,
                result: None,
            });
        }
        let response = match self.core.take_kit_egress_response() {
            Ok(value) => value,
            Err(error) => return Err(self.fail(KitArtifactErrorV2::Core(error))),
        };
        let progress = match self.transfer.as_mut() {
            Some(transfer) => transfer.accept_response(response.as_slice()),
            None => Err(KitArtifactErrorV2::ExportArtifactInvariant),
        };
        drop(response);
        let progress = match progress {
            Ok(value) => value,
            Err(error) => return Err(self.fail(error)),
        };
        match progress {
            KitExportProgressV2::Continue => {
                let request = match self.transfer.as_mut() {
                    Some(transfer) => transfer.next_request(),
                    None => Err(KitArtifactErrorV2::ExportArtifactInvariant),
                };
                let request = match request {
                    Ok(value) => value,
                    Err(error) => return Err(self.fail(error)),
                };
                let outbound = match self.core.begin_kit_egress(request.bytes()) {
                    Ok(value) => value,
                    Err(error) => {
                        drop(request);
                        return Err(self.fail(KitArtifactErrorV2::Core(error)));
                    }
                };
                drop(request);
                Ok(KitDeliveryReceiveOutcomeV2 {
                    consumed: outer.consumed,
                    outbound: Some(outbound),
                    result: None,
                })
            }
            KitExportProgressV2::Complete(result) => {
                drop(self.transfer.take());
                self.result = Some(result);
                Ok(KitDeliveryReceiveOutcomeV2 {
                    consumed: outer.consumed,
                    outbound: None,
                    result: Some(result),
                })
            }
        }
    }

    /// Stable completed facts; unavailable before the one route finishes.
    pub const fn result(&self) -> Option<KitExportResultV2> {
        self.result
    }

    fn fail(&mut self, error: KitArtifactErrorV2) -> KitArtifactErrorV2 {
        self.failed = true;
        if let Some(transfer) = self.transfer.as_mut() {
            let _ = transfer.normalize_outer_error(error);
        }
        drop(self.transfer.take());
        self.core.terminate_kit(Interruption::OperationFailed);
        error
    }
}

impl Drop for KitDeliverySessionV2 {
    fn drop(&mut self) {
        if !self.failed && self.result.is_none() {
            self.core.terminate_kit(Interruption::OperationFailed);
        }
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

    const fn public(self) -> KitExportRouteV2 {
        match self {
            Self::Sd { .. } => KitExportRouteV2::Sd,
            Self::Bbqr { .. } => KitExportRouteV2::Bbqr,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhaseV2 {
    ReadyBegin,
    AwaitBegin,
    ReadyWrite,
    AwaitWrite { accepted_total: u32 },
    ReadyFinish,
    AwaitFinish,
    Complete,
    Failed,
}

/// One selected no-fallback raw transaction transfer.
pub(crate) struct KitExportTransferV2 {
    profile: NormalProfileV2,
    route: SelectedRouteV2,
    raw: Option<RawOwnerV2>,
    offset: u32,
    phase: PhaseV2,
    sd_receipt: Option<KitSdReceiptV2>,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl KitExportTransferV2 {
    fn select(
        artifacts: KitExportArtifactsV2,
        action: KitExportActionV2,
    ) -> Result<Self, KitArtifactErrorV2> {
        let route = match action {
            KitExportActionV2::Sd { caller_nonce } => SelectedRouteV2::Sd { caller_nonce },
            KitExportActionV2::Bbqr { non_final_part_len } => {
                encoded_part_count(artifacts.raw.bytes.len(), usize::from(non_final_part_len))
                    .map_err(|_| KitArtifactErrorV2::ExportRouteUnavailable)?;
                SelectedRouteV2::Bbqr { non_final_part_len }
            }
        };
        Ok(Self {
            profile: artifacts.profile,
            route,
            raw: Some(artifacts.raw),
            offset: 0,
            phase: PhaseV2::ReadyBegin,
            sd_receipt: None,
            txid: artifacts.txid,
            wtxid: artifacts.wtxid,
        })
    }

    pub fn next_request(&mut self) -> Result<KitExportRequestV2, KitArtifactErrorV2> {
        let result = match self.phase {
            PhaseV2::ReadyBegin => self.build_begin(),
            PhaseV2::ReadyWrite => self.build_write(),
            PhaseV2::ReadyFinish => self.build_finish(),
            PhaseV2::Complete | PhaseV2::Failed => Err(KitArtifactErrorV2::Finished),
            PhaseV2::AwaitBegin | PhaseV2::AwaitWrite { .. } | PhaseV2::AwaitFinish => {
                Err(KitArtifactErrorV2::InvalidTransition)
            }
        };
        result.map_err(|error| self.fail(error))
    }

    pub fn accept_response(
        &mut self,
        response: &[u8],
    ) -> Result<KitExportProgressV2, KitArtifactErrorV2> {
        let result = match self.phase {
            PhaseV2::AwaitBegin => self.accept_begin(response),
            PhaseV2::AwaitWrite { accepted_total } => self.accept_write(response, accepted_total),
            PhaseV2::AwaitFinish => self.accept_finish(response),
            PhaseV2::Complete | PhaseV2::Failed => Err(KitArtifactErrorV2::Finished),
            PhaseV2::ReadyBegin | PhaseV2::ReadyWrite | PhaseV2::ReadyFinish => {
                Err(KitArtifactErrorV2::InvalidTransition)
            }
        };
        result.map_err(|error| self.fail(error))
    }

    pub(crate) fn normalize_outer_error(
        &mut self,
        error: KitArtifactErrorV2,
    ) -> KitArtifactErrorV2 {
        self.fail(error)
    }

    fn raw(&self) -> Result<&RawOwnerV2, KitArtifactErrorV2> {
        self.raw
            .as_ref()
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)
    }

    fn build_begin(&mut self) -> Result<KitExportRequestV2, KitArtifactErrorV2> {
        let total_len = self.raw()?.facts.serialized_len;
        let bytes = match self.route {
            SelectedRouteV2::Sd { caller_nonce } => build_sd_begin(total_len, &caller_nonce)?,
            SelectedRouteV2::Bbqr { non_final_part_len } => {
                build_bbqr_begin(total_len, non_final_part_len)?
            }
        };
        self.phase = PhaseV2::AwaitBegin;
        Ok(KitExportRequestV2 { bytes })
    }

    fn build_write(&mut self) -> Result<KitExportRequestV2, KitArtifactErrorV2> {
        let raw = self.raw()?;
        let offset = usize::try_from(self.offset)
            .map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
        let end = offset
            .checked_add(MAX_CHUNK_BYTES)
            .map_or(raw.bytes.len(), |candidate| candidate.min(raw.bytes.len()));
        let chunk = raw
            .bytes
            .as_slice()
            .get(offset..end)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
        let accepted_total =
            u32::try_from(end).map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
        let request_len = 16usize
            .checked_add(chunk.len())
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
        let mut bytes = WipingVec::try_zeroed(request_len)
            .map_err(|_| KitArtifactErrorV2::Core(CoreError::AllocationFailed))?;
        if encode_normal_egress_write(self.offset, chunk, bytes.as_mut_slice()) != Some(request_len)
        {
            return Err(KitArtifactErrorV2::ExportArtifactInvariant);
        }
        self.phase = PhaseV2::AwaitWrite { accepted_total };
        Ok(KitExportRequestV2 { bytes })
    }

    fn build_finish(&mut self) -> Result<KitExportRequestV2, KitArtifactErrorV2> {
        let mut bytes = WipingVec::try_zeroed(8)
            .map_err(|_| KitArtifactErrorV2::Core(CoreError::AllocationFailed))?;
        bytes.as_mut_slice().copy_from_slice(&[
            INNER_VERSION,
            Operation::EgressFinish.wire_value(),
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        self.phase = PhaseV2::AwaitFinish;
        Ok(KitExportRequestV2 { bytes })
    }

    fn accept_begin(&mut self, response: &[u8]) -> Result<KitExportProgressV2, KitArtifactErrorV2> {
        let expected = ExpectedNormalEgressResponseV2::Begin {
            sink: self.route.sink(),
            artifact: NormalEgressArtifactV2::RawTransaction,
        };
        match parse_normal_egress_response(response, expected) {
            Ok(NormalEgressResponseV2::Begin) => {
                self.phase = PhaseV2::ReadyWrite;
                Ok(KitExportProgressV2::Continue)
            }
            Ok(_) => Err(KitArtifactErrorV2::ExportReceiptMismatch),
            Err(error) => Err(KitArtifactErrorV2::Core(error)),
        }
    }

    fn accept_write(
        &mut self,
        response: &[u8],
        accepted_total: u32,
    ) -> Result<KitExportProgressV2, KitArtifactErrorV2> {
        let total_len = self.raw()?.facts.serialized_len;
        let expected = ExpectedNormalEgressResponseV2::Write {
            sink: self.route.sink(),
            artifact: NormalEgressArtifactV2::RawTransaction,
            accepted_total,
        };
        match parse_normal_egress_response(response, expected) {
            Ok(NormalEgressResponseV2::Write {
                accepted_total: actual,
            }) if actual == accepted_total => {
                self.offset = actual;
                self.phase = if actual == total_len {
                    PhaseV2::ReadyFinish
                } else {
                    PhaseV2::ReadyWrite
                };
                Ok(KitExportProgressV2::Continue)
            }
            Ok(_) => Err(KitArtifactErrorV2::ExportReceiptMismatch),
            Err(error) => Err(KitArtifactErrorV2::Core(error)),
        }
    }

    fn accept_finish(
        &mut self,
        response: &[u8],
    ) -> Result<KitExportProgressV2, KitArtifactErrorV2> {
        let serialized_len = self.raw()?.facts.serialized_len;
        let expected = ExpectedNormalEgressResponseV2::Finish {
            sink: self.route.sink(),
            artifact: NormalEgressArtifactV2::RawTransaction,
            total_len: serialized_len,
        };
        let parsed = parse_normal_egress_response(response, expected).map_err(|error| {
            if matches!(self.route, SelectedRouteV2::Bbqr { .. }) {
                KitArtifactErrorV2::BbqrVerificationMismatch
            } else {
                KitArtifactErrorV2::Core(error)
            }
        })?;
        match (self.route, parsed) {
            (SelectedRouteV2::Sd { .. }, NormalEgressResponseV2::SdFinish) => {
                self.sd_receipt = Some(KitSdReceiptV2 {
                    total_len: serialized_len,
                });
            }
            (
                SelectedRouteV2::Bbqr { non_final_part_len },
                NormalEgressResponseV2::BbqrFinish {
                    frame_count,
                    encoded_frames,
                },
            ) => verify_bbqr(self.raw()?, non_final_part_len, frame_count, encoded_frames)?,
            _ => return Err(KitArtifactErrorV2::ExportReceiptMismatch),
        }
        let facts = self.raw()?.facts;
        drop(self.raw.take());
        self.phase = PhaseV2::Complete;
        Ok(KitExportProgressV2::Complete(KitExportResultV2 {
            profile: self.profile,
            route: self.route.public(),
            raw_transaction: facts,
            sd_receipt: self.sd_receipt,
            txid: self.txid,
            wtxid: self.wtxid,
        }))
    }

    fn fail(&mut self, error: KitArtifactErrorV2) -> KitArtifactErrorV2 {
        self.phase = PhaseV2::Failed;
        drop(self.raw.take());
        error
    }
}

impl Drop for KitExportTransferV2 {
    fn drop(&mut self) {
        crate::wipe::bytes(&mut self.txid);
        crate::wipe::bytes(&mut self.wtxid);
    }
}

fn build_sd_begin(
    total_len: u32,
    caller_nonce: &[u8; 16],
) -> Result<WipingVec, KitArtifactErrorV2> {
    let suffix = b"-final.tx";
    let filename_len = 35usize
        .checked_add(suffix.len())
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
    let body_len = 9usize
        .checked_add(filename_len)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
    let complete_len = 8usize
        .checked_add(body_len)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
    let mut output = WipingVec::try_zeroed(complete_len)
        .map_err(|_| KitArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    let body_len_u32 =
        u32::try_from(body_len).map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
    let aux_len = filename_len
        .checked_add(1)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
    let aux_len_u16 =
        u16::try_from(aux_len).map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
    output
        .as_mut_slice()
        .get_mut(..8)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&[
            INNER_VERSION,
            Operation::EgressBegin.wire_value(),
            0,
            0,
            body_len_u32.to_le_bytes()[0],
            body_len_u32.to_le_bytes()[1],
            body_len_u32.to_le_bytes()[2],
            body_len_u32.to_le_bytes()[3],
        ]);
    output
        .as_mut_slice()
        .get_mut(8..16)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(&[
            NormalEgressSinkV2::Sd.wire_value(),
            NormalEgressArtifactV2::RawTransaction.wire_value(),
            total_len.to_le_bytes()[0],
            total_len.to_le_bytes()[1],
            total_len.to_le_bytes()[2],
            total_len.to_le_bytes()[3],
            aux_len_u16.to_le_bytes()[0],
            aux_len_u16.to_le_bytes()[1],
        ]);
    let filename_len_u8 =
        u8::try_from(filename_len).map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
    *output
        .as_mut_slice()
        .get_mut(16)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)? = filename_len_u8;
    output
        .as_mut_slice()
        .get_mut(17..20)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(b"qk-");
    let mut cursor = 20usize;
    for byte in caller_nonce {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        let table = b"0123456789abcdef";
        *output
            .as_mut_slice()
            .get_mut(cursor)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)? = *table
            .get(hi)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
        cursor = cursor
            .checked_add(1)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
        *output
            .as_mut_slice()
            .get_mut(cursor)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)? = *table
            .get(lo)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
        cursor = cursor
            .checked_add(1)
            .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
    }
    let end = cursor
        .checked_add(suffix.len())
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?;
    output
        .as_mut_slice()
        .get_mut(cursor..end)
        .ok_or(KitArtifactErrorV2::ExportArtifactInvariant)?
        .copy_from_slice(suffix);
    Ok(output)
}

fn build_bbqr_begin(
    total_len: u32,
    non_final_part_len: u16,
) -> Result<WipingVec, KitArtifactErrorV2> {
    let mut output = WipingVec::try_zeroed(18)
        .map_err(|_| KitArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    output.as_mut_slice().copy_from_slice(&[
        INNER_VERSION,
        Operation::EgressBegin.wire_value(),
        0,
        0,
        10,
        0,
        0,
        0,
        NormalEgressSinkV2::Bbqr.wire_value(),
        NormalEgressArtifactV2::RawTransaction.wire_value(),
        total_len.to_le_bytes()[0],
        total_len.to_le_bytes()[1],
        total_len.to_le_bytes()[2],
        total_len.to_le_bytes()[3],
        2,
        0,
        non_final_part_len.to_le_bytes()[0],
        non_final_part_len.to_le_bytes()[1],
    ]);
    Ok(output)
}

fn verify_bbqr(
    raw: &RawOwnerV2,
    non_final_part_len: u16,
    frame_count: u16,
    encoded_frames: &[u8],
) -> Result<(), KitArtifactErrorV2> {
    let expected_count = encoded_part_count(raw.bytes.len(), usize::from(non_final_part_len))
        .map_err(|_| KitArtifactErrorV2::BbqrVerificationMismatch)?;
    if frame_count != expected_count {
        return Err(KitArtifactErrorV2::BbqrVerificationMismatch);
    }
    let mut output = WipingVec::try_zeroed(MAX_TOTAL_DECODED_BYTES)
        .map_err(|_| KitArtifactErrorV2::Core(CoreError::AllocationFailed))?;
    let fixed: &mut [u8; MAX_TOTAL_DECODED_BYTES] = output
        .as_mut_slice()
        .try_into()
        .map_err(|_| KitArtifactErrorV2::ExportArtifactInvariant)?;
    let mut reassembler = Reassembler::new_typed(BbqrFileType::Transaction, fixed);
    let mut cursor = 0usize;
    for submitted in 0..frame_count {
        let length_end = cursor
            .checked_add(2)
            .ok_or(KitArtifactErrorV2::BbqrVerificationMismatch)?;
        let length_bytes: &[u8; 2] = encoded_frames
            .get(cursor..length_end)
            .ok_or(KitArtifactErrorV2::BbqrVerificationMismatch)?
            .try_into()
            .map_err(|_| KitArtifactErrorV2::BbqrVerificationMismatch)?;
        let frame_len = usize::from(u16::from_le_bytes(*length_bytes));
        let frame_end = length_end
            .checked_add(frame_len)
            .ok_or(KitArtifactErrorV2::BbqrVerificationMismatch)?;
        let frame = encoded_frames
            .get(length_end..frame_end)
            .ok_or(KitArtifactErrorV2::BbqrVerificationMismatch)?;
        let mut expected = WipingArray::<MAX_FRAME_TEXT_BYTES>::zeroed();
        let expected_len = encode_typed_frame(
            BbqrFileType::Transaction,
            raw.bytes.as_slice(),
            usize::from(non_final_part_len),
            submitted,
            expected.as_mut_array(),
        )
        .map_err(|_| KitArtifactErrorV2::BbqrVerificationMismatch)?;
        if expected_len != frame.len() || expected.as_array().get(..expected_len) != Some(frame) {
            return Err(KitArtifactErrorV2::BbqrVerificationMismatch);
        }
        let progress = reassembler
            .submit(frame)
            .map_err(|_| KitArtifactErrorV2::BbqrVerificationMismatch)?;
        if progress.declared_parts != frame_count
            || progress.received_parts != submitted.saturating_add(1)
            || progress.was_duplicate
            || progress.complete != (submitted.saturating_add(1) == frame_count)
        {
            return Err(KitArtifactErrorV2::BbqrVerificationMismatch);
        }
        cursor = frame_end;
    }
    if cursor != encoded_frames.len()
        || reassembler
            .payload()
            .map_err(|_| KitArtifactErrorV2::BbqrVerificationMismatch)?
            != raw.bytes.as_slice()
    {
        return Err(KitArtifactErrorV2::BbqrVerificationMismatch);
    }
    Ok(())
}
