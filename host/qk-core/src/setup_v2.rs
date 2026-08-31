//! QK-DEC-145 HOST-only v2 provisioning orchestration.
//!
//! The owner joins the exact manual-keypad ceremony, unchanged provisioning
//! leaf, public-only card mock, and purpose-bound qk-core transport. It owns
//! every secret/share-bearing buffer and exposes artifact bytes only through
//! complete [`CoreOutbound`] frames.

use crate::capability::{
    CardBPublicBindingV2, CardInstanceV2, CardMockErrorV2, CardPresence, CoreDeviceGrants,
    CoreScreen, KeypadKey,
};
use crate::error::{CoreError, Interruption};
use crate::session::{CoreMode, CoreOutbound, CoreReceiveEvent, CoreSession};
use crate::setup_artifact_v2::{A1PrintArtifactV2, KitPrintArtifactV2};
use crate::{sha256, wipe};
use core::fmt;
use qk_provisioning::{
    HostProvisioningRunV2, KitPageDispositionV2, KitSetupErrorV2, ProvisioningArtifactsV2,
    ProvisioningError,
};

pub const MANUAL_TRANSCRIPT_BYTES_V2: usize = 100;
const PURPOSE_COUNT: usize = 4;
const KIT_PAGE_COUNT: usize = 4;

/// Exact v2 ceremony purpose order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyPurposeV2 {
    SeedA,
    SignerB,
    KitR,
    A2,
}

impl CeremonyPurposeV2 {
    const fn at(index: usize) -> Option<Self> {
        Some(match index {
            0 => Self::SeedA,
            1 => Self::SignerB,
            2 => Self::KitR,
            3 => Self::A2,
            _ => return None,
        })
    }

    const fn tag(self) -> u8 {
        match self {
            Self::SeedA => 1,
            Self::SignerB => 2,
            Self::KitR => 3,
            Self::A2 => 4,
        }
    }
}

/// Exact setup entropy selector; DiceGrid remains unavailable in this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyInputModeV2 {
    DiceGrid,
    ManualKeypad,
}

/// One immutable spare-card choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpareBChoiceV2 {
    NoSpare,
    ProvisionSpare,
}

/// Exact visible setup topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupStageV2 {
    SetupStart,
    TierSelection,
    EntropyModeSelection,
    CeremonyInput,
    CeremonyEcho,
    CeremonyConfirm,
    CeremonyCommitment,
    DerivationExplanation,
    ProvisioningResult,
    ProvisionB,
    VerifyB,
    SpareBSelection,
    ProvisionSpareB,
    VerifySpareB,
    CreateA1,
    ScanBackA1,
    CoordinatorMaterial,
    CreateTwoKits,
    VerifyTwoKits,
    Rehearsal,
    SetupReady,
    CompletedWiped,
}

impl SetupStageV2 {
    const fn screen(self) -> CoreScreen {
        match self {
            Self::SetupStart => CoreScreen::SetupStart,
            Self::TierSelection => CoreScreen::TierSelection,
            Self::EntropyModeSelection => CoreScreen::EntropyModeSelection,
            Self::CeremonyInput => CoreScreen::CeremonyInput,
            Self::CeremonyEcho => CoreScreen::CeremonyEcho,
            Self::CeremonyConfirm => CoreScreen::CeremonyConfirm,
            Self::CeremonyCommitment => CoreScreen::CeremonyCommitment,
            Self::DerivationExplanation => CoreScreen::DerivationExplanation,
            Self::ProvisioningResult => CoreScreen::ProvisioningResult,
            Self::ProvisionB => CoreScreen::ProvisionB,
            Self::VerifyB => CoreScreen::VerifyB,
            Self::SpareBSelection => CoreScreen::SpareBSelection,
            Self::ProvisionSpareB => CoreScreen::ProvisionSpareB,
            Self::VerifySpareB => CoreScreen::VerifySpareB,
            Self::CreateA1 => CoreScreen::CreateA1,
            Self::ScanBackA1 => CoreScreen::ScanBackA1,
            Self::CoordinatorMaterial => CoreScreen::CoordinatorMaterial,
            Self::CreateTwoKits => CoreScreen::CreateTwoKits,
            Self::VerifyTwoKits => CoreScreen::VerifyTwoKits,
            Self::Rehearsal => CoreScreen::Rehearsal,
            Self::SetupReady => CoreScreen::SetupReady,
            Self::CompletedWiped => CoreScreen::CompletedWiped,
        }
    }
}

/// Closed local setup rejection vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupErrorV2 {
    InvalidTransition,
    DiceGridUnavailable,
    InvalidFaceKey,
    TranscriptFull,
    EmptyDelete,
    TranscriptCountIncomplete,
    TranscriptReuse,
    ProvisioningRejected,
    CommitmentInvariant,
    CardAbsent,
    CardInstanceAlreadyProvisioned,
    CardBindingMismatch,
    SpareChoiceAlreadyMade,
    ArtifactInvariant,
    A1ScanbackMismatch,
    PrintReceiptMismatch,
    SetupFinished,
    Interrupted(Interruption),
    Core(CoreError),
}

impl SetupErrorV2 {
    /// Stable name carrying no hostile or secret bytes.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidTransition => "InvalidTransition",
            Self::DiceGridUnavailable => "DiceGridUnavailable",
            Self::InvalidFaceKey => "InvalidFaceKey",
            Self::TranscriptFull => "TranscriptFull",
            Self::EmptyDelete => "EmptyDelete",
            Self::TranscriptCountIncomplete => "TranscriptCountIncomplete",
            Self::TranscriptReuse => "TranscriptReuse",
            Self::ProvisioningRejected => "ProvisioningRejected",
            Self::CommitmentInvariant => "CommitmentInvariant",
            Self::CardAbsent => "CardAbsent",
            Self::CardInstanceAlreadyProvisioned => "CardInstanceAlreadyProvisioned",
            Self::CardBindingMismatch => "CardBindingMismatch",
            Self::SpareChoiceAlreadyMade => "SpareChoiceAlreadyMade",
            Self::ArtifactInvariant => "ArtifactInvariant",
            Self::A1ScanbackMismatch => "A1ScanbackMismatch",
            Self::PrintReceiptMismatch => "PrintReceiptMismatch",
            Self::SetupFinished => "SetupFinished",
            Self::Interrupted(reason) => reason.name(),
            Self::Core(_) => "Core",
        }
    }
}

impl fmt::Display for SetupErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for SetupErrorV2 {}

/// Public wallet facts selected by result and coordinator screens.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SetupPublicFactsV2 {
    account_xpubs: [[u8; 111]; 2],
    descriptors: [[u8; 306]; 2],
    wallet_id: [u8; 32],
    first_scripts: [[u8; 34]; 2],
    first_addresses: [[u8; 62]; 2],
}

impl SetupPublicFactsV2 {
    pub const fn account_xpubs(&self) -> &[[u8; 111]; 2] {
        &self.account_xpubs
    }

    pub const fn descriptors(&self) -> &[[u8; 306]; 2] {
        &self.descriptors
    }

    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn first_scripts(&self) -> &[[u8; 34]; 2] {
        &self.first_scripts
    }

    pub const fn first_addresses(&self) -> &[[u8; 62]; 2] {
        &self.first_addresses
    }
}

/// Borrow-only screen facts. Transcript bytes occur only at Echo/Confirm.
pub enum SetupScreenV2<'a> {
    Stage(SetupStageV2),
    EntropyModeSelection {
        selected: EntropyInputModeV2,
    },
    CeremonyInput {
        purpose: CeremonyPurposeV2,
        count: usize,
    },
    CeremonyEcho {
        purpose: CeremonyPurposeV2,
        transcript: &'a [u8],
    },
    CeremonyConfirm {
        purpose: CeremonyPurposeV2,
        transcript: &'a [u8],
    },
    CeremonyCommitment {
        purpose: CeremonyPurposeV2,
        commitment: &'a [u8; 32],
    },
    ProvisioningResult(&'a SetupPublicFactsV2),
    CoordinatorMaterial(&'a SetupPublicFactsV2),
}

/// Stable application result; recoverable rejections are values, not errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupOutcomeV2 {
    TransportPending,
    Continue(SetupStageV2),
    StatePreserving(SetupErrorV2),
    CompletedWiped,
}

/// One setup transition and its optional complete QKIP request.
pub struct SetupProgressV2 {
    outcome: SetupOutcomeV2,
    outbound: Option<CoreOutbound>,
}

impl SetupProgressV2 {
    pub const fn outcome(&self) -> SetupOutcomeV2 {
        self.outcome
    }

    pub const fn outbound(&self) -> Option<&CoreOutbound> {
        self.outbound.as_ref()
    }

    pub fn into_outbound(self) -> Option<CoreOutbound> {
        self.outbound
    }
}

/// Stream consumption result plus any automatically chained request.
pub struct SetupReceiveOutcomeV2 {
    consumed: usize,
    outcome: SetupOutcomeV2,
    outbound: Option<CoreOutbound>,
}

impl SetupReceiveOutcomeV2 {
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    pub const fn outcome(&self) -> SetupOutcomeV2 {
        self.outcome
    }

    pub const fn outbound(&self) -> Option<&CoreOutbound> {
        self.outbound.as_ref()
    }

    pub fn into_outbound(self) -> Option<CoreOutbound> {
        self.outbound
    }
}

struct SecretTranscriptV2 {
    bytes: [u8; MANUAL_TRANSCRIPT_BYTES_V2],
    len: usize,
}

struct SecretNonceV2([u8; 12]);

impl SecretNonceV2 {
    fn take(source: &mut [u8; 12]) -> Self {
        let bytes = *source;
        wipe::bytes(source);
        Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl Drop for SecretNonceV2 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.0);
    }
}

impl SecretTranscriptV2 {
    const fn empty() -> Self {
        Self {
            bytes: [0; MANUAL_TRANSCRIPT_BYTES_V2],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    fn push(&mut self, face: u8) -> bool {
        let Some(slot) = self.bytes.get_mut(self.len) else {
            return false;
        };
        *slot = face;
        self.len = self.len.saturating_add(1);
        true
    }

    fn delete(&mut self) -> bool {
        let Some(next_len) = self.len.checked_sub(1) else {
            return false;
        };
        let Some(slot) = self.bytes.get_mut(next_len) else {
            return false;
        };
        wipe::bytes(core::slice::from_mut(slot));
        self.len = next_len;
        true
    }

    fn clear(&mut self) {
        wipe::bytes(&mut self.bytes);
        self.len = 0;
    }
}

impl Drop for SecretTranscriptV2 {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrintStateV2 {
    A1Begin,
    A1Write,
    A1Finish,
    KitBegin,
    KitWrite,
    KitFinish,
}

/// Complete setup session owning the QKIP endpoint and every setup buffer.
///
/// This type deliberately implements no clone, copy, debug, display,
/// serializer, or logger trait.
pub struct SetupSessionV2 {
    core: CoreSession,
    stage: Option<SetupStageV2>,
    entropy_mode: EntropyInputModeV2,
    transcripts: [SecretTranscriptV2; PURPOSE_COUNT],
    purpose_index: usize,
    commitment: [u8; 32],
    commitment_live: bool,
    nonce: [u8; 12],
    nonce_live: bool,
    run: Option<Box<HostProvisioningRunV2>>,
    facts: Option<SetupPublicFactsV2>,
    a1_artifact: Option<A1PrintArtifactV2>,
    kit_pages: [Option<KitPrintArtifactV2>; KIT_PAGE_COUNT],
    kit_page_index: usize,
    kit_receipt_wallet: Option<[u8; 32]>,
    print_state: Option<PrintStateV2>,
    spare_choice: Option<SpareBChoiceV2>,
    close_pending: bool,
    terminal_error: Option<SetupErrorV2>,
}

impl SetupSessionV2 {
    /// Start one exact Setup-mode QKIP session with one caller-bound nonce.
    pub fn start(
        grants: CoreDeviceGrants,
        nonce: &mut [u8; 12],
    ) -> Result<(Self, CoreOutbound), SetupErrorV2> {
        let mut owned_nonce = *nonce;
        wipe::bytes(nonce);
        match CoreSession::start(CoreMode::Setup, grants) {
            Ok((core, outbound)) => Ok((Self::from_core(core, owned_nonce), outbound)),
            Err(error) => {
                wipe::bytes(&mut owned_nonce);
                Err(SetupErrorV2::Core(error))
            }
        }
    }

    /// Deterministic public-data constructor for unit and ring-fenced fuzz use.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn fuzz_start(
        namespace: [u8; 12],
        last_counter: u32,
        grants: CoreDeviceGrants,
        nonce: &mut [u8; 12],
    ) -> Result<(Self, CoreOutbound), SetupErrorV2> {
        let mut owned_nonce = *nonce;
        wipe::bytes(nonce);
        let started =
            crate::session::fuzz_start_session(namespace, last_counter, CoreMode::Setup, grants);
        match started {
            Ok((core, outbound)) => Ok((Self::from_core(core, owned_nonce), outbound)),
            Err(error) => {
                wipe::bytes(&mut owned_nonce);
                Err(SetupErrorV2::Core(error))
            }
        }
    }

    fn from_core(core: CoreSession, nonce: [u8; 12]) -> Self {
        Self {
            core,
            stage: None,
            entropy_mode: EntropyInputModeV2::DiceGrid,
            transcripts: core::array::from_fn(|_| SecretTranscriptV2::empty()),
            purpose_index: 0,
            commitment: [0; 32],
            commitment_live: false,
            nonce,
            nonce_live: true,
            run: None,
            facts: None,
            a1_artifact: None,
            kit_pages: core::array::from_fn(|_| None),
            kit_page_index: 0,
            kit_receipt_wallet: None,
            print_state: None,
            spare_choice: None,
            close_pending: false,
            terminal_error: None,
        }
    }

    pub const fn stage(&self) -> Option<SetupStageV2> {
        self.stage
    }

    pub const fn entropy_mode(&self) -> EntropyInputModeV2 {
        self.entropy_mode
    }

    pub fn retained_counts(&self) -> [usize; PURPOSE_COUNT] {
        core::array::from_fn(|index| {
            self.transcripts
                .get(index)
                .map_or(0, |transcript| transcript.len)
        })
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal_error.is_some() || self.stage == Some(SetupStageV2::CompletedWiped)
    }

    pub const fn terminal_error(&self) -> Option<SetupErrorV2> {
        self.terminal_error
    }

    pub const fn public_facts(&self) -> Option<&SetupPublicFactsV2> {
        self.facts.as_ref()
    }

    pub fn screen(&self) -> Option<SetupScreenV2<'_>> {
        let stage = self.stage?;
        let purpose = CeremonyPurposeV2::at(self.purpose_index);
        Some(match stage {
            SetupStageV2::EntropyModeSelection => SetupScreenV2::EntropyModeSelection {
                selected: self.entropy_mode,
            },
            SetupStageV2::CeremonyInput => SetupScreenV2::CeremonyInput {
                purpose: purpose?,
                count: self.current_transcript()?.len,
            },
            SetupStageV2::CeremonyEcho => SetupScreenV2::CeremonyEcho {
                purpose: purpose?,
                transcript: self.current_transcript()?.as_slice(),
            },
            SetupStageV2::CeremonyConfirm => SetupScreenV2::CeremonyConfirm {
                purpose: purpose?,
                transcript: self.current_transcript()?.as_slice(),
            },
            SetupStageV2::CeremonyCommitment if self.commitment_live => {
                SetupScreenV2::CeremonyCommitment {
                    purpose: purpose?,
                    commitment: &self.commitment,
                }
            }
            SetupStageV2::ProvisioningResult => {
                SetupScreenV2::ProvisioningResult(self.facts.as_ref()?)
            }
            SetupStageV2::CoordinatorMaterial => {
                SetupScreenV2::CoordinatorMaterial(self.facts.as_ref()?)
            }
            _ => SetupScreenV2::Stage(stage),
        })
    }

    /// Consume at most one QKIP frame and automatically chain only the exact
    /// pending print or A1 scan-back operation.
    pub fn receive(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<SetupReceiveOutcomeV2, SetupErrorV2> {
        if self.is_terminal() {
            return Err(SetupErrorV2::SetupFinished);
        }
        let received = match self.core.receive(input, ancillary_present) {
            Ok(received) => received,
            Err(error) => {
                return Err(self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed))
            }
        };
        let consumed = received.consumed();
        let progress = self.handle_receive_event(received.event())?;
        Ok(SetupReceiveOutcomeV2 {
            consumed,
            outcome: progress.outcome,
            outbound: progress.outbound,
        })
    }

    fn handle_receive_event(
        &mut self,
        event: CoreReceiveEvent,
    ) -> Result<SetupProgressV2, SetupErrorV2> {
        let progress = match event {
            CoreReceiveEvent::NeedMore => SetupProgressV2 {
                outcome: SetupOutcomeV2::TransportPending,
                outbound: None,
            },
            CoreReceiveEvent::SessionReady if self.stage.is_none() => {
                self.advance(SetupStageV2::SetupStart, None)?
            }
            CoreReceiveEvent::A1PrintBegan if self.print_state == Some(PrintStateV2::A1Begin) => {
                let outbound = {
                    let Some(artifact) = self.a1_artifact.as_ref() else {
                        return Err(self.fail(
                            SetupErrorV2::ArtifactInvariant,
                            Interruption::OperationFailed,
                        ));
                    };
                    self.core.write_a1_print(artifact.as_bytes())
                };
                let outbound = match outbound {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.print_state = Some(PrintStateV2::A1Write);
                self.continued(Some(outbound))
            }
            CoreReceiveEvent::A1PrintWritten { .. }
                if self.print_state == Some(PrintStateV2::A1Write) =>
            {
                let outbound = match self.core.finish_a1_print() {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.print_state = Some(PrintStateV2::A1Finish);
                self.continued(Some(outbound))
            }
            CoreReceiveEvent::A1PrintFinished { .. }
                if self.print_state == Some(PrintStateV2::A1Finish) =>
            {
                self.print_state = None;
                self.advance(SetupStageV2::ScanBackA1, None)?;
                let outbound = match self.core.begin_a1_scanback() {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.continued(Some(outbound))
            }
            CoreReceiveEvent::KitPrintBegan if self.print_state == Some(PrintStateV2::KitBegin) => {
                let outbound = {
                    let Some(artifact) = self
                        .kit_pages
                        .get(self.kit_page_index)
                        .and_then(Option::as_ref)
                    else {
                        return Err(self.fail(
                            SetupErrorV2::ArtifactInvariant,
                            Interruption::OperationFailed,
                        ));
                    };
                    self.core.write_kit_print(artifact.as_bytes())
                };
                let outbound = match outbound {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.print_state = Some(PrintStateV2::KitWrite);
                self.continued(Some(outbound))
            }
            CoreReceiveEvent::KitPrintWritten { .. }
                if self.print_state == Some(PrintStateV2::KitWrite) =>
            {
                let outbound = match self.core.finish_kit_print() {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.print_state = Some(PrintStateV2::KitFinish);
                self.continued(Some(outbound))
            }
            CoreReceiveEvent::KitPrintFinished { .. }
                if self.print_state == Some(PrintStateV2::KitFinish) =>
            {
                self.finish_kit_page()?
            }
            CoreReceiveEvent::IngressBegan {
                source: crate::Source::CameraA1Candidate,
                ..
            } if self.stage == Some(SetupStageV2::ScanBackA1) => {
                let outbound = match self.core.request_a1_scanback_chunk() {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.continued(Some(outbound))
            }
            CoreReceiveEvent::IngressChunk { final_chunk, .. }
                if self.stage == Some(SetupStageV2::ScanBackA1) =>
            {
                if !final_chunk {
                    let outbound = match self.core.request_a1_scanback_chunk() {
                        Ok(outbound) => outbound,
                        Err(error) => {
                            return Err(
                                self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                            )
                        }
                    };
                    self.continued(Some(outbound))
                } else {
                    self.finish_a1_scanback()?
                }
            }
            CoreReceiveEvent::SessionClosed if self.close_pending => {
                self.close_pending = false;
                self.cleanup_owned();
                self.stage = Some(SetupStageV2::CompletedWiped);
                SetupProgressV2 {
                    outcome: SetupOutcomeV2::CompletedWiped,
                    outbound: None,
                }
            }
            CoreReceiveEvent::A1PrintBegan
            | CoreReceiveEvent::KitPrintBegan
            | CoreReceiveEvent::A1PrintWritten { .. }
            | CoreReceiveEvent::KitPrintWritten { .. }
            | CoreReceiveEvent::A1PrintFinished { .. }
            | CoreReceiveEvent::KitPrintFinished { .. } => {
                return Err(self.fail(
                    SetupErrorV2::PrintReceiptMismatch,
                    Interruption::OperationFailed,
                ))
            }
            CoreReceiveEvent::SessionReady
            | CoreReceiveEvent::IngressBegan { .. }
            | CoreReceiveEvent::IngressChunk { .. }
            | CoreReceiveEvent::SessionClosed => {
                return Err(self.fail(
                    SetupErrorV2::InvalidTransition,
                    Interruption::OperationFailed,
                ))
            }
        };
        Ok(progress)
    }

    /// Begin the one A1 print only from CreateA1.
    pub fn begin_a1_print(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        if self.stage != Some(SetupStageV2::CreateA1)
            || self.print_state.is_some()
            || self.a1_artifact.is_none()
        {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let outbound = match self.core.begin_a1_print() {
            Ok(outbound) => outbound,
            Err(error) => {
                return Err(self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed))
            }
        };
        self.print_state = Some(PrintStateV2::A1Begin);
        Ok(self.continued(Some(outbound)))
    }

    /// Consume the retained provisioning run once and start page one of four.
    pub fn begin_kit_print(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        if self.stage != Some(SetupStageV2::CreateTwoKits)
            || self.print_state.is_some()
            || self.kit_pages.iter().any(Option::is_some)
        {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let Some(run) = self.run.take() else {
            return Err(self.fail(
                SetupErrorV2::ArtifactInvariant,
                Interruption::OperationFailed,
            ));
        };
        let mut page_index = 0usize;
        let mut artifact_invariant = false;
        let generated = run.emit_two_kit_copies(|page| {
            let Some(destination) = self.kit_pages.get_mut(page_index) else {
                artifact_invariant = true;
                return KitPageDispositionV2::Rejected;
            };
            let Some(artifact) = KitPrintArtifactV2::try_from_page(page) else {
                artifact_invariant = true;
                return KitPageDispositionV2::Rejected;
            };
            *destination = Some(artifact);
            page_index = page_index.saturating_add(1);
            KitPageDispositionV2::Accepted
        });
        let receipt = match generated {
            Ok(receipt) if !artifact_invariant && page_index == KIT_PAGE_COUNT => receipt,
            Ok(_)
            | Err(KitSetupErrorV2::A1NotReady | KitSetupErrorV2::KitEncodingInvariant)
            | Err(KitSetupErrorV2::PrintRejected) => {
                return Err(self.fail(
                    SetupErrorV2::ArtifactInvariant,
                    Interruption::OperationFailed,
                ))
            }
        };
        let wallet_id = receipt.wallet_id();
        if self.facts.as_ref().map(SetupPublicFactsV2::wallet_id) != Some(wallet_id) {
            return Err(self.fail(
                SetupErrorV2::ArtifactInvariant,
                Interruption::OperationFailed,
            ));
        }
        self.kit_receipt_wallet = Some(wallet_id);
        self.kit_page_index = 0;
        let outbound = match self.core.begin_kit_print() {
            Ok(outbound) => outbound,
            Err(error) => {
                return Err(self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed))
            }
        };
        self.print_state = Some(PrintStateV2::KitBegin);
        Ok(self.continued(Some(outbound)))
    }

    fn current_transcript(&self) -> Option<&SecretTranscriptV2> {
        self.transcripts.get(self.purpose_index)
    }

    fn finish_kit_page(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        let Some(page) = self.kit_pages.get_mut(self.kit_page_index) else {
            return Err(self.fail(
                SetupErrorV2::ArtifactInvariant,
                Interruption::OperationFailed,
            ));
        };
        if page.is_none() {
            return Err(self.fail(
                SetupErrorV2::ArtifactInvariant,
                Interruption::OperationFailed,
            ));
        }
        drop(page.take());
        let Some(next) = self.kit_page_index.checked_add(1) else {
            return Err(self.fail(
                SetupErrorV2::ArtifactInvariant,
                Interruption::OperationFailed,
            ));
        };
        self.kit_page_index = next;
        if next < KIT_PAGE_COUNT {
            let outbound = match self.core.begin_kit_print() {
                Ok(outbound) => outbound,
                Err(error) => {
                    return Err(self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed))
                }
            };
            self.print_state = Some(PrintStateV2::KitBegin);
            return Ok(self.continued(Some(outbound)));
        }
        self.print_state = None;
        self.advance(SetupStageV2::VerifyTwoKits, None)
    }

    fn finish_a1_scanback(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        let matched = {
            let Some(artifact) = self.a1_artifact.as_ref() else {
                return Err(self.fail(
                    SetupErrorV2::ArtifactInvariant,
                    Interruption::OperationFailed,
                ));
            };
            self.core.consume_a1_scanback(artifact.as_bytes())
        };
        match matched {
            Ok(true) => {
                drop(self.a1_artifact.take());
                self.advance(SetupStageV2::CoordinatorMaterial, None)
            }
            Ok(false) => Err(self.fail(
                SetupErrorV2::A1ScanbackMismatch,
                Interruption::OperationFailed,
            )),
            Err(error) => Err(self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)),
        }
    }

    fn current_transcript_mut(&mut self) -> Option<&mut SecretTranscriptV2> {
        self.transcripts.get_mut(self.purpose_index)
    }

    /// Route one logical key through the owned keypad and exact setup state.
    pub fn apply_key(&mut self, key: KeypadKey) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        let key = match self.core.setup_read_key(key) {
            Ok(key) => key,
            Err(error) => {
                return Err(self.fail(SetupErrorV2::Core(error), Interruption::CapabilityFailed))
            }
        };
        if key == KeypadKey::CancelBack {
            return Err(self.fail(
                SetupErrorV2::Interrupted(Interruption::Cancelled),
                Interruption::Cancelled,
            ));
        }
        let stage = self.stage.ok_or_else(|| {
            self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            )
        })?;
        match stage {
            SetupStageV2::SetupStart if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::TierSelection, None)
            }
            SetupStageV2::TierSelection if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::EntropyModeSelection, None)
            }
            SetupStageV2::EntropyModeSelection => self.apply_entropy_key(key),
            SetupStageV2::CeremonyInput => self.apply_entry_key(key),
            SetupStageV2::CeremonyEcho if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::CeremonyConfirm, None)
            }
            SetupStageV2::CeremonyConfirm if key == KeypadKey::EqualsConfirmEnter => {
                self.commit_current_transcript()
            }
            SetupStageV2::CeremonyCommitment if key == KeypadKey::EqualsConfirmEnter => {
                self.finish_current_commitment()
            }
            SetupStageV2::DerivationExplanation if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::ProvisioningResult, None)
            }
            SetupStageV2::ProvisioningResult if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::ProvisionB, None)
            }
            SetupStageV2::CoordinatorMaterial if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::CreateTwoKits, None)
            }
            SetupStageV2::VerifyTwoKits if key == KeypadKey::EqualsConfirmEnter => {
                if self.kit_receipt_wallet != self.facts.as_ref().map(SetupPublicFactsV2::wallet_id)
                {
                    return Err(self.fail(
                        SetupErrorV2::ArtifactInvariant,
                        Interruption::OperationFailed,
                    ));
                }
                self.advance(SetupStageV2::Rehearsal, None)
            }
            SetupStageV2::Rehearsal if key == KeypadKey::EqualsConfirmEnter => {
                self.advance(SetupStageV2::SetupReady, None)
            }
            SetupStageV2::SetupReady if key == KeypadKey::EqualsConfirmEnter => {
                let outbound = match self.core.begin_close() {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        return Err(
                            self.fail(SetupErrorV2::Core(error), Interruption::OperationFailed)
                        )
                    }
                };
                self.close_pending = true;
                Ok(SetupProgressV2 {
                    outcome: SetupOutcomeV2::TransportPending,
                    outbound: Some(outbound),
                })
            }
            _ => Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            )),
        }
    }

    /// Camera input cannot widen the unavailable DiceGrid path.
    pub fn camera_presented(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        if self.stage == Some(SetupStageV2::EntropyModeSelection)
            && self.entropy_mode == EntropyInputModeV2::DiceGrid
        {
            return Ok(self.state_preserving(SetupErrorV2::DiceGridUnavailable));
        }
        Err(self.fail(
            SetupErrorV2::InvalidTransition,
            Interruption::OperationFailed,
        ))
    }

    /// Apply one closed interruption and clear every setup owner first.
    pub fn interrupt(&mut self, reason: Interruption) -> Result<Interruption, SetupErrorV2> {
        if self.is_terminal() {
            return Err(SetupErrorV2::SetupFinished);
        }
        self.cleanup_owned();
        self.terminal_error = Some(SetupErrorV2::Interrupted(reason));
        self.stage = None;
        self.core.terminate_setup(reason);
        Ok(reason)
    }

    /// Observe the one card-slot presence seam; removal terminates setup.
    pub fn observe_card(&mut self, presence: CardPresence) -> Result<CardPresence, SetupErrorV2> {
        self.require_active()?;
        match self.core.observe_card(presence) {
            Ok(CardPresence::Present) => Ok(CardPresence::Present),
            Ok(CardPresence::Absent) => {
                self.cleanup_owned();
                self.terminal_error = Some(SetupErrorV2::Interrupted(Interruption::CardRemoved));
                self.stage = None;
                Err(SetupErrorV2::Interrupted(Interruption::CardRemoved))
            }
            Err(error) => Err(self.fail(SetupErrorV2::Core(error), Interruption::CapabilityFailed)),
        }
    }

    /// Execute the public-only card binding for the screen's exact instance.
    pub fn provision_card(
        &mut self,
        instance: CardInstanceV2,
    ) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        let expected_stage = match instance {
            CardInstanceV2::Required => SetupStageV2::ProvisionB,
            CardInstanceV2::Spare => SetupStageV2::ProvisionSpareB,
        };
        if self.stage != Some(expected_stage) {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let binding = self.card_binding(instance)?;
        if let Err(error) = self.core.setup_provision_b(binding) {
            let mapped = map_card_error(error);
            let reason = if mapped == SetupErrorV2::CardAbsent {
                Interruption::CardRemoved
            } else {
                Interruption::OperationFailed
            };
            return Err(self.fail(mapped, reason));
        }
        let next = match instance {
            CardInstanceV2::Required => SetupStageV2::VerifyB,
            CardInstanceV2::Spare => SetupStageV2::VerifySpareB,
        };
        self.advance(next, None)
    }

    /// Verify byte equality with the exact previously recorded public binding.
    pub fn verify_card(
        &mut self,
        instance: CardInstanceV2,
    ) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        let expected_stage = match instance {
            CardInstanceV2::Required => SetupStageV2::VerifyB,
            CardInstanceV2::Spare => SetupStageV2::VerifySpareB,
        };
        if self.stage != Some(expected_stage) {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let binding = self.card_binding(instance)?;
        if let Err(error) = self.core.setup_verify_b(binding) {
            let mapped = map_card_error(error);
            let reason = if mapped == SetupErrorV2::CardAbsent {
                Interruption::CardRemoved
            } else {
                Interruption::OperationFailed
            };
            return Err(self.fail(mapped, reason));
        }
        let next = match instance {
            CardInstanceV2::Required => SetupStageV2::SpareBSelection,
            CardInstanceV2::Spare => SetupStageV2::CreateA1,
        };
        self.advance(next, None)
    }

    /// Record the one immutable spare choice.
    pub fn select_spare(
        &mut self,
        choice: SpareBChoiceV2,
    ) -> Result<SetupProgressV2, SetupErrorV2> {
        self.require_active()?;
        if self.spare_choice.is_some() {
            return Err(self.fail(
                SetupErrorV2::SpareChoiceAlreadyMade,
                Interruption::OperationFailed,
            ));
        }
        if self.stage != Some(SetupStageV2::SpareBSelection) {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        self.spare_choice = Some(choice);
        let next = match choice {
            SpareBChoiceV2::NoSpare => SetupStageV2::CreateA1,
            SpareBChoiceV2::ProvisionSpare => SetupStageV2::ProvisionSpareB,
        };
        self.advance(next, None)
    }

    fn apply_entropy_key(&mut self, key: KeypadKey) -> Result<SetupProgressV2, SetupErrorV2> {
        match key {
            KeypadKey::FourLeft => {
                self.entropy_mode = EntropyInputModeV2::DiceGrid;
                Ok(self.continued(None))
            }
            KeypadKey::SixRight => {
                self.entropy_mode = EntropyInputModeV2::ManualKeypad;
                Ok(self.continued(None))
            }
            KeypadKey::EqualsConfirmEnter if self.entropy_mode == EntropyInputModeV2::DiceGrid => {
                Ok(self.state_preserving(SetupErrorV2::DiceGridUnavailable))
            }
            KeypadKey::EqualsConfirmEnter => self.advance(SetupStageV2::CeremonyInput, None),
            _ => Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            )),
        }
    }

    fn apply_entry_key(&mut self, key: KeypadKey) -> Result<SetupProgressV2, SetupErrorV2> {
        let face = face_byte(key);
        if let Some(face) = face {
            let Some(transcript) = self.current_transcript_mut() else {
                return Err(self.fail(
                    SetupErrorV2::InvalidTransition,
                    Interruption::OperationFailed,
                ));
            };
            if transcript.len == MANUAL_TRANSCRIPT_BYTES_V2 {
                return Ok(self.state_preserving(SetupErrorV2::TranscriptFull));
            }
            if !transcript.push(face) {
                return Err(self.fail(
                    SetupErrorV2::InvalidTransition,
                    Interruption::OperationFailed,
                ));
            }
            return Ok(self.continued(None));
        }
        match key {
            KeypadKey::CeDelete => {
                let Some(transcript) = self.current_transcript_mut() else {
                    return Err(self.fail(
                        SetupErrorV2::InvalidTransition,
                        Interruption::OperationFailed,
                    ));
                };
                if !transcript.delete() {
                    return Ok(self.state_preserving(SetupErrorV2::EmptyDelete));
                }
                Ok(self.continued(None))
            }
            KeypadKey::EqualsConfirmEnter => {
                if self.current_transcript().map_or(0, |value| value.len)
                    != MANUAL_TRANSCRIPT_BYTES_V2
                {
                    return Ok(self.state_preserving(SetupErrorV2::TranscriptCountIncomplete));
                }
                self.advance(SetupStageV2::CeremonyEcho, None)
            }
            KeypadKey::Seven
            | KeypadKey::EightUp
            | KeypadKey::Nine
            | KeypadKey::Zero
            | KeypadKey::Decimal
            | KeypadKey::Plus
            | KeypadKey::Minus
            | KeypadKey::Multiply
            | KeypadKey::Divide
            | KeypadKey::Percent => Ok(self.state_preserving(SetupErrorV2::InvalidFaceKey)),
            KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::FourLeft
            | KeypadKey::Five
            | KeypadKey::SixRight
            | KeypadKey::CancelBack => Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            )),
        }
    }

    fn commit_current_transcript(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        let Some(purpose) = CeremonyPurposeV2::at(self.purpose_index) else {
            return Err(self.fail(
                SetupErrorV2::CommitmentInvariant,
                Interruption::OperationFailed,
            ));
        };
        let Some(transcript) = self.transcripts.get(self.purpose_index) else {
            return Err(self.fail(
                SetupErrorV2::CommitmentInvariant,
                Interruption::OperationFailed,
            ));
        };
        if transcript.len != MANUAL_TRANSCRIPT_BYTES_V2
            || !sha256::ceremony_transcript_commitment(
                purpose.tag(),
                &transcript.bytes,
                &mut self.commitment,
            )
        {
            return Err(self.fail(
                SetupErrorV2::CommitmentInvariant,
                Interruption::OperationFailed,
            ));
        }
        self.commitment_live = true;
        self.advance(SetupStageV2::CeremonyCommitment, None)
    }

    fn finish_current_commitment(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        if !self.commitment_live {
            return Err(self.fail(
                SetupErrorV2::CommitmentInvariant,
                Interruption::OperationFailed,
            ));
        }
        self.clear_commitment();
        let Some(next) = self.purpose_index.checked_add(1) else {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        };
        if next < PURPOSE_COUNT {
            self.purpose_index = next;
            return self.advance(SetupStageV2::CeremonyInput, None);
        }
        self.derive_and_encrypt()
    }

    fn derive_and_encrypt(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {
        let [seed_a, signer_b, kit_r, a2] = &self.transcripts;
        let derived = HostProvisioningRunV2::from_manual_dice([
            seed_a.as_slice(),
            signer_b.as_slice(),
            kit_r.as_slice(),
            a2.as_slice(),
        ]);
        self.clear_transcripts();
        let mut run = match derived {
            Ok(run) => Box::new(run),
            Err(ProvisioningError::TranscriptReuse) => {
                return Err(self.fail(SetupErrorV2::TranscriptReuse, Interruption::OperationFailed))
            }
            Err(_) => {
                return Err(self.fail(
                    SetupErrorV2::ProvisioningRejected,
                    Interruption::OperationFailed,
                ))
            }
        };
        let nonce = SecretNonceV2::take(&mut self.nonce);
        self.nonce_live = false;
        let encrypted = run.encrypt_a1(nonce.as_bytes());
        drop(nonce);
        let artifacts = match encrypted {
            Ok(artifacts) => artifacts,
            Err(_) => {
                drop(run);
                return Err(self.fail(
                    SetupErrorV2::ProvisioningRejected,
                    Interruption::OperationFailed,
                ));
            }
        };
        let (facts, a1_artifact) = split_artifacts(artifacts);
        self.run = Some(run);
        self.facts = Some(facts);
        self.a1_artifact = Some(a1_artifact);
        self.advance(SetupStageV2::DerivationExplanation, None)
    }

    fn card_binding(
        &mut self,
        instance: CardInstanceV2,
    ) -> Result<CardBPublicBindingV2, SetupErrorV2> {
        let Some(facts) = self.facts.as_ref() else {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        };
        let Some(account_xpub) = facts.account_xpubs.get(1).copied() else {
            return Err(self.fail(
                SetupErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        };
        Ok(CardBPublicBindingV2::new(
            instance,
            facts.wallet_id,
            account_xpub,
        ))
    }

    fn advance(
        &mut self,
        stage: SetupStageV2,
        outbound: Option<CoreOutbound>,
    ) -> Result<SetupProgressV2, SetupErrorV2> {
        if let Err(error) = self.core.setup_show(stage.screen()) {
            return Err(self.fail(SetupErrorV2::Core(error), Interruption::CapabilityFailed));
        }
        self.stage = Some(stage);
        Ok(SetupProgressV2 {
            outcome: if stage == SetupStageV2::CompletedWiped {
                SetupOutcomeV2::CompletedWiped
            } else {
                SetupOutcomeV2::Continue(stage)
            },
            outbound,
        })
    }

    fn continued(&self, outbound: Option<CoreOutbound>) -> SetupProgressV2 {
        SetupProgressV2 {
            outcome: self
                .stage
                .map_or(SetupOutcomeV2::TransportPending, SetupOutcomeV2::Continue),
            outbound,
        }
    }

    fn state_preserving(&self, error: SetupErrorV2) -> SetupProgressV2 {
        SetupProgressV2 {
            outcome: SetupOutcomeV2::StatePreserving(error),
            outbound: None,
        }
    }

    fn require_active(&self) -> Result<(), SetupErrorV2> {
        if self.is_terminal() || self.close_pending {
            Err(SetupErrorV2::SetupFinished)
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: SetupErrorV2, reason: Interruption) -> SetupErrorV2 {
        if !self.is_terminal() {
            self.cleanup_owned();
            self.stage = None;
            self.terminal_error = Some(error);
            if reason == Interruption::OperationFailed {
                self.core.setup_fail();
            } else {
                self.core.terminate_setup(reason);
            }
        }
        error
    }

    fn clear_transcripts(&mut self) {
        for transcript in &mut self.transcripts {
            transcript.clear();
        }
    }

    fn clear_commitment(&mut self) {
        if self.commitment_live {
            wipe::bytes(&mut self.commitment);
            self.commitment_live = false;
        }
    }

    fn clear_nonce(&mut self) {
        if self.nonce_live {
            wipe::bytes(&mut self.nonce);
            self.nonce_live = false;
        }
    }

    fn cleanup_owned(&mut self) {
        self.clear_transcripts();
        self.clear_commitment();
        self.clear_nonce();
        drop(self.run.take());
        drop(self.a1_artifact.take());
        for page in &mut self.kit_pages {
            drop(page.take());
        }
        self.kit_page_index = 0;
        self.kit_receipt_wallet = None;
        self.print_state = None;
        self.close_pending = false;
        self.facts = None;
    }
}

impl Drop for SetupSessionV2 {
    fn drop(&mut self) {
        self.cleanup_owned();
    }
}

fn split_artifacts(artifacts: ProvisioningArtifactsV2) -> (SetupPublicFactsV2, A1PrintArtifactV2) {
    let ProvisioningArtifactsV2 {
        account_xpubs,
        descriptors,
        wallet_id,
        first_scripts,
        first_addresses,
        mut a1_capsule,
    } = artifacts;
    let a1_artifact = A1PrintArtifactV2::take(&mut a1_capsule);
    (
        SetupPublicFactsV2 {
            account_xpubs,
            descriptors,
            wallet_id,
            first_scripts,
            first_addresses,
        },
        a1_artifact,
    )
}

const fn face_byte(key: KeypadKey) -> Option<u8> {
    Some(match key {
        KeypadKey::One => b'1',
        KeypadKey::TwoDown => b'2',
        KeypadKey::Three => b'3',
        KeypadKey::FourLeft => b'4',
        KeypadKey::Five => b'5',
        KeypadKey::SixRight => b'6',
        _ => return None,
    })
}

const fn map_card_error(error: CardMockErrorV2) -> SetupErrorV2 {
    match error {
        CardMockErrorV2::CardAbsent => SetupErrorV2::CardAbsent,
        CardMockErrorV2::CardInstanceAlreadyProvisioned => {
            SetupErrorV2::CardInstanceAlreadyProvisioned
        }
        CardMockErrorV2::CardBindingMismatch => SetupErrorV2::CardBindingMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{MockCardSlot, MockDisplay, MockKeypad};

    fn test_setup() -> SetupSessionV2 {
        let grants = CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Present)),
            false,
        )
        .expect("exact setup grants");
        let mut nonce = [0x5a; 12];
        let (setup, _opening) = SetupSessionV2::fuzz_start([0x31; 12], 0, grants, &mut nonce)
            .expect("deterministic setup");
        assert_eq!(nonce, [0; 12]);
        setup
    }

    #[test]
    fn incomplete_transport_is_distinct_before_ready_and_while_closing() {
        let mut setup = test_setup();
        let pending = setup
            .handle_receive_event(CoreReceiveEvent::NeedMore)
            .expect("opening fragment remains live");
        assert_eq!(pending.outcome(), SetupOutcomeV2::TransportPending);
        assert_eq!(setup.stage(), None);
        assert!(!setup.is_terminal());

        setup.stage = Some(SetupStageV2::SetupReady);
        setup.close_pending = true;
        let pending = setup
            .handle_receive_event(CoreReceiveEvent::NeedMore)
            .expect("closing fragment remains live");
        assert_eq!(pending.outcome(), SetupOutcomeV2::TransportPending);
        assert_eq!(setup.stage(), Some(SetupStageV2::SetupReady));
        assert!(!setup.is_terminal());
    }

    #[test]
    fn unexpected_receipt_and_unrelated_event_have_distinct_names() {
        let mut print_setup = test_setup();
        let print_error = match print_setup.handle_receive_event(CoreReceiveEvent::A1PrintBegan) {
            Ok(_) => panic!("unexpected print receipt accepted"),
            Err(error) => error,
        };
        assert_eq!(print_error, SetupErrorV2::PrintReceiptMismatch);
        assert_eq!(print_error.name(), "PrintReceiptMismatch");
        assert_eq!(print_setup.terminal_error(), Some(print_error));

        let mut unrelated_setup = test_setup();
        let unrelated_error =
            match unrelated_setup.handle_receive_event(CoreReceiveEvent::IngressBegan {
                source: crate::Source::CameraA1Candidate,
                total_len: 67,
            }) {
                Ok(_) => panic!("unrelated event accepted"),
                Err(error) => error,
            };
        assert_eq!(unrelated_error, SetupErrorV2::InvalidTransition);
        assert_eq!(unrelated_error.name(), "InvalidTransition");
        assert_eq!(unrelated_setup.terminal_error(), Some(unrelated_error));
    }
}
