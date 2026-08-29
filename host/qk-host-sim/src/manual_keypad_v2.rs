//! Slice-5 HOST-only owner for four v2 manual-keypad dice transcripts.
//!
//! This fixed-memory seam joins the P0.1 logical keypad to the unchanged
//! `HostProvisioningRunV2::from_manual_dice` validator and the v2 borrow-only
//! ceremony screens. It is not a renderer, physical keypad driver, entropy
//! source, DiceGrid path, or target-cleanup claim.

use crate::screen_flow::KeypadKey;
use crate::screen_flow_v2::{
    CeremonyPurposeV2, EntropyInputModeV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, ScreenFlowV2, ScreenKindV2, ScreenV2, WipingReasonV2,
};
use qk_provisioning::{HostProvisioningRunV2, ProvisioningError};

pub const MANUAL_TRANSCRIPT_BYTES_V2: usize = 100;
const PURPOSE_COUNT: usize = 4;

struct SecretTranscriptV2 {
    bytes: Box<[u8; MANUAL_TRANSCRIPT_BYTES_V2]>,
    len: usize,
}

impl SecretTranscriptV2 {
    fn empty() -> Self {
        Self {
            bytes: Box::new([0; MANUAL_TRANSCRIPT_BYTES_V2]),
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push(&mut self, face: u8) {
        self.bytes[self.len] = face;
        self.len += 1;
    }

    fn delete(&mut self) {
        self.len -= 1;
        // A deleted face is no longer retained ceremony material.
        wipe(&mut self.bytes[self.len..=self.len]);
    }

    fn wipe(&mut self) {
        wipe(self.bytes.as_mut());
        self.len = 0;
    }
}

impl Drop for SecretTranscriptV2 {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualKeypadErrorV2 {
    InvalidFaceKey,
    TranscriptFull,
    EmptyDelete,
    TranscriptCountIncomplete,
    TranscriptReuse,
    InvalidTransition,
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
    ProvisioningRejected(ProvisioningError),
    Finished,
}

impl ManualKeypadErrorV2 {
    /// Stable non-secret outcome name for HOST routing and tests.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidFaceKey => "InvalidFaceKey",
            Self::TranscriptFull => "TranscriptFull",
            Self::EmptyDelete => "EmptyDelete",
            Self::TranscriptCountIncomplete => "TranscriptCountIncomplete",
            Self::TranscriptReuse => "TranscriptReuse",
            Self::InvalidTransition => "InvalidTransition",
            Self::Cancelled => "Cancelled",
            Self::OperationFailed => "OperationFailed",
            Self::MediaRemoved => "MediaRemoved",
            Self::CardRemoved => "CardRemoved",
            Self::SessionTimeout => "SessionTimeout",
            Self::Shutdown => "Shutdown",
            Self::Restart => "Restart",
            Self::PowerLoss => "PowerLoss",
            Self::ProvisioningRejected(_) => "ProvisioningRejected",
            Self::Finished => "Finished",
        }
    }
}

impl core::fmt::Display for ManualKeypadErrorV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for ManualKeypadErrorV2 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualKeypadEventV2 {
    Key(KeypadKey),
    CommitmentReady([u8; 32]),
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

#[derive(Clone, Copy)]
pub struct ManualTranscriptViewV2<'a> {
    bytes: &'a [u8],
}

impl<'a> ManualTranscriptViewV2<'a> {
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Clone, Copy)]
pub enum ManualKeypadScreenV2<'a> {
    Entry {
        purpose: CeremonyPurposeV2,
        count: usize,
    },
    Echo {
        purpose: CeremonyPurposeV2,
        transcript: ManualTranscriptViewV2<'a>,
    },
    Confirm {
        purpose: CeremonyPurposeV2,
        transcript: ManualTranscriptViewV2<'a>,
    },
    AwaitingCommitment {
        purpose: CeremonyPurposeV2,
    },
    Commitment {
        purpose: CeremonyPurposeV2,
        commitment: [u8; 32],
    },
    Complete,
    Failed(ManualKeypadErrorV2),
}

pub enum ManualKeypadOutcomeV2 {
    Continue,
    ProvisioningReady(Box<HostProvisioningRunV2>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryStageV2 {
    Entry,
    Echo,
    Confirm,
    AwaitingCommitment,
    Commitment,
    Complete,
    Failed(ManualKeypadErrorV2),
}

/// Owning v2 manual-entry scope.
///
/// This owner deliberately implements no `Clone`, `Copy`, `Debug`, or
/// display trait and offers no method that returns an owned transcript.
pub struct ManualKeypadSessionV2 {
    flow: Option<ScreenFlowV2>,
    transcripts: [SecretTranscriptV2; PURPOSE_COUNT],
    purpose_index: usize,
    stage: EntryStageV2,
}

impl ManualKeypadSessionV2 {
    /// Bind to a v2 setup flow already positioned at manual-keypad ceremony
    /// input. A mismatched flow is terminated rather than widened.
    pub fn begin(mut flow: ScreenFlowV2) -> Result<Self, ManualKeypadErrorV2> {
        let valid = flow.flow_kind() == FlowKindV2::Setup
            && matches!(
                flow.screen(),
                Some(ScreenV2::CeremonyInput {
                    purpose: CeremonyPurposeV2::SeedA,
                    mode: EntropyInputModeV2::ManualKeypad,
                })
            );
        if !valid {
            flow.terminate_manual_keypad(WipingReasonV2::InvalidTransition);
            return Err(ManualKeypadErrorV2::InvalidTransition);
        }
        Ok(Self {
            flow: Some(flow),
            transcripts: core::array::from_fn(|_| SecretTranscriptV2::empty()),
            purpose_index: 0,
            stage: EntryStageV2::Entry,
        })
    }

    #[must_use]
    pub fn screen(&self) -> ManualKeypadScreenV2<'_> {
        let Some(purpose) = purpose_at(self.purpose_index) else {
            return ManualKeypadScreenV2::Failed(ManualKeypadErrorV2::InvalidTransition);
        };
        let transcript = ManualTranscriptViewV2 {
            bytes: self.transcripts[self.purpose_index].as_slice(),
        };
        match self.stage {
            EntryStageV2::Entry => ManualKeypadScreenV2::Entry {
                purpose,
                count: self.transcripts[self.purpose_index].len,
            },
            EntryStageV2::Echo => ManualKeypadScreenV2::Echo {
                purpose,
                transcript,
            },
            EntryStageV2::Confirm => ManualKeypadScreenV2::Confirm {
                purpose,
                transcript,
            },
            EntryStageV2::AwaitingCommitment => {
                ManualKeypadScreenV2::AwaitingCommitment { purpose }
            }
            EntryStageV2::Commitment => {
                let commitment = match self.flow.as_ref().and_then(ScreenFlowV2::screen) {
                    Some(ScreenV2::CeremonyCommitment {
                        commitment: view, ..
                    }) => *view.bytes(),
                    _ => {
                        return ManualKeypadScreenV2::Failed(ManualKeypadErrorV2::InvalidTransition)
                    }
                };
                ManualKeypadScreenV2::Commitment {
                    purpose,
                    commitment,
                }
            }
            EntryStageV2::Complete => ManualKeypadScreenV2::Complete,
            EntryStageV2::Failed(error) => ManualKeypadScreenV2::Failed(error),
        }
    }

    #[must_use]
    pub fn retained_counts(&self) -> [usize; PURPOSE_COUNT] {
        core::array::from_fn(|index| self.transcripts[index].len)
    }

    #[must_use]
    pub fn terminal(&self) -> Option<FlowTerminalV2> {
        self.flow.as_ref().and_then(ScreenFlowV2::terminal)
    }

    /// Apply one closed manual-entry event. The four recoverable input errors
    /// return `Err` without changing the current stage, count, or bytes.
    pub fn apply(
        &mut self,
        event: ManualKeypadEventV2,
    ) -> Result<ManualKeypadOutcomeV2, ManualKeypadErrorV2> {
        if matches!(self.stage, EntryStageV2::Complete | EntryStageV2::Failed(_)) {
            return Err(ManualKeypadErrorV2::Finished);
        }
        if let Some((error, reason)) = interruption(event) {
            self.fail(error, reason);
            return Err(error);
        }

        match (self.stage, event) {
            (EntryStageV2::Entry, ManualKeypadEventV2::Key(key)) => self.apply_entry_key(key),
            (EntryStageV2::Echo, ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                if !self.flow_mut()?.confirm_manual_keypad_echo() {
                    self.fail(
                        ManualKeypadErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    );
                    return Err(ManualKeypadErrorV2::InvalidTransition);
                }
                self.stage = EntryStageV2::Confirm;
                Ok(ManualKeypadOutcomeV2::Continue)
            }
            (EntryStageV2::Confirm, ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                if !self.flow_mut()?.complete_manual_keypad_confirmation() {
                    self.fail(
                        ManualKeypadErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    );
                    return Err(ManualKeypadErrorV2::InvalidTransition);
                }
                self.stage = EntryStageV2::AwaitingCommitment;
                Ok(ManualKeypadOutcomeV2::Continue)
            }
            (
                EntryStageV2::AwaitingCommitment,
                ManualKeypadEventV2::CommitmentReady(commitment),
            ) => {
                let reached =
                    self.apply_root_kind(FlowEventV2::CeremonyCommitmentReady(commitment));
                if reached != Some(ScreenKindV2::CeremonyCommitment) {
                    self.fail(
                        ManualKeypadErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    );
                    return Err(ManualKeypadErrorV2::InvalidTransition);
                }
                self.stage = EntryStageV2::Commitment;
                Ok(ManualKeypadOutcomeV2::Continue)
            }
            (EntryStageV2::Commitment, ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.finish_commitment()
            }
            (_, ManualKeypadEventV2::Key(KeypadKey::CancelBack)) => {
                self.fail(ManualKeypadErrorV2::Cancelled, WipingReasonV2::Cancelled);
                Err(ManualKeypadErrorV2::Cancelled)
            }
            _ => {
                self.fail(
                    ManualKeypadErrorV2::InvalidTransition,
                    WipingReasonV2::InvalidTransition,
                );
                Err(ManualKeypadErrorV2::InvalidTransition)
            }
        }
    }

    /// Recover the v2 root only after successful four-purpose completion.
    pub fn take_completed_flow(&mut self) -> Option<ScreenFlowV2> {
        if self.stage == EntryStageV2::Complete {
            self.flow.take()
        } else {
            None
        }
    }

    fn apply_entry_key(
        &mut self,
        key: KeypadKey,
    ) -> Result<ManualKeypadOutcomeV2, ManualKeypadErrorV2> {
        let transcript = &mut self.transcripts[self.purpose_index];
        match key {
            KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::FourLeft
            | KeypadKey::Five
            | KeypadKey::SixRight => {
                if transcript.len == MANUAL_TRANSCRIPT_BYTES_V2 {
                    return Err(ManualKeypadErrorV2::TranscriptFull);
                }
                let Some(face) = face_byte(key) else {
                    return Err(ManualKeypadErrorV2::InvalidFaceKey);
                };
                transcript.push(face);
            }
            KeypadKey::CeDelete => {
                if transcript.len == 0 {
                    return Err(ManualKeypadErrorV2::EmptyDelete);
                }
                transcript.delete();
            }
            KeypadKey::EqualsConfirmEnter => {
                if transcript.len != MANUAL_TRANSCRIPT_BYTES_V2 {
                    return Err(ManualKeypadErrorV2::TranscriptCountIncomplete);
                }
                if !self
                    .flow
                    .as_mut()
                    .is_some_and(ScreenFlowV2::begin_manual_keypad_echo)
                {
                    self.fail(
                        ManualKeypadErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    );
                    return Err(ManualKeypadErrorV2::InvalidTransition);
                }
                self.stage = EntryStageV2::Echo;
            }
            KeypadKey::CancelBack => {
                self.fail(ManualKeypadErrorV2::Cancelled, WipingReasonV2::Cancelled);
                return Err(ManualKeypadErrorV2::Cancelled);
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
            | KeypadKey::Percent => return Err(ManualKeypadErrorV2::InvalidFaceKey),
        }
        Ok(ManualKeypadOutcomeV2::Continue)
    }

    fn finish_commitment(&mut self) -> Result<ManualKeypadOutcomeV2, ManualKeypadErrorV2> {
        let expected = if self.purpose_index + 1 == PURPOSE_COUNT {
            ScreenKindV2::DerivationExplanation
        } else {
            ScreenKindV2::CeremonyInput
        };
        let reached = self.apply_root_kind(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter));
        if reached != Some(expected) {
            self.fail(
                ManualKeypadErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            );
            return Err(ManualKeypadErrorV2::InvalidTransition);
        }

        if self.purpose_index + 1 != PURPOSE_COUNT {
            self.purpose_index += 1;
            self.stage = EntryStageV2::Entry;
            return Ok(ManualKeypadOutcomeV2::Continue);
        }

        let transcripts = [
            self.transcripts[0].as_slice(),
            self.transcripts[1].as_slice(),
            self.transcripts[2].as_slice(),
            self.transcripts[3].as_slice(),
        ];
        match HostProvisioningRunV2::from_manual_dice(transcripts) {
            Ok(run) => {
                self.wipe_transcripts();
                self.stage = EntryStageV2::Complete;
                Ok(ManualKeypadOutcomeV2::ProvisioningReady(Box::new(run)))
            }
            Err(ProvisioningError::TranscriptReuse) => {
                self.fail(
                    ManualKeypadErrorV2::TranscriptReuse,
                    WipingReasonV2::OperationFailed,
                );
                Err(ManualKeypadErrorV2::TranscriptReuse)
            }
            Err(error) => {
                let result = ManualKeypadErrorV2::ProvisioningRejected(error);
                self.fail(result, WipingReasonV2::OperationFailed);
                Err(result)
            }
        }
    }

    fn flow_mut(&mut self) -> Result<&mut ScreenFlowV2, ManualKeypadErrorV2> {
        self.flow.as_mut().ok_or(ManualKeypadErrorV2::Finished)
    }

    /// Collapse the scoped root outcome to a copy before later owner access.
    fn apply_root_kind(&mut self, event: FlowEventV2<'static>) -> Option<ScreenKindV2> {
        let flow = self.flow.as_mut()?;
        match flow.apply(event).ok()? {
            FlowApplyOutcomeV2::Continue(kind) => Some(kind),
            _ => None,
        }
    }

    fn fail(&mut self, error: ManualKeypadErrorV2, reason: WipingReasonV2) {
        self.wipe_transcripts();
        if let Some(flow) = self.flow.as_mut() {
            flow.terminate_manual_keypad(reason);
        }
        self.stage = EntryStageV2::Failed(error);
    }

    fn wipe_transcripts(&mut self) {
        for transcript in &mut self.transcripts {
            transcript.wipe();
        }
    }
}

impl Drop for ManualKeypadSessionV2 {
    fn drop(&mut self) {
        self.wipe_transcripts();
        if !matches!(self.stage, EntryStageV2::Complete | EntryStageV2::Failed(_)) {
            if let Some(flow) = self.flow.as_mut() {
                flow.terminate_manual_keypad(WipingReasonV2::Cancelled);
            }
        }
    }
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

const fn purpose_at(index: usize) -> Option<CeremonyPurposeV2> {
    Some(match index {
        0 => CeremonyPurposeV2::SeedA,
        1 => CeremonyPurposeV2::SignerB,
        2 => CeremonyPurposeV2::KitR,
        3 => CeremonyPurposeV2::A2,
        _ => return None,
    })
}

fn interruption(event: ManualKeypadEventV2) -> Option<(ManualKeypadErrorV2, WipingReasonV2)> {
    Some(match event {
        ManualKeypadEventV2::OperationFailed => (
            ManualKeypadErrorV2::OperationFailed,
            WipingReasonV2::OperationFailed,
        ),
        ManualKeypadEventV2::MediaRemoved => (
            ManualKeypadErrorV2::MediaRemoved,
            WipingReasonV2::MediaRemoved,
        ),
        ManualKeypadEventV2::CardRemoved => (
            ManualKeypadErrorV2::CardRemoved,
            WipingReasonV2::CardRemoved,
        ),
        ManualKeypadEventV2::SessionTimeout => (
            ManualKeypadErrorV2::SessionTimeout,
            WipingReasonV2::SessionTimeout,
        ),
        ManualKeypadEventV2::Shutdown => (ManualKeypadErrorV2::Shutdown, WipingReasonV2::Shutdown),
        ManualKeypadEventV2::Restart => (ManualKeypadErrorV2::Restart, WipingReasonV2::Restart),
        ManualKeypadEventV2::PowerLoss => {
            (ManualKeypadErrorV2::PowerLoss, WipingReasonV2::PowerLoss)
        }
        ManualKeypadEventV2::Key(_) | ManualKeypadEventV2::CommitmentReady(_) => return None,
    })
}

/// Established qk-a1 HOST cleanup shape: force a visible post-fill borrow at
/// a non-inlined boundary so the compiler may not discard the clearing store.
#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}
