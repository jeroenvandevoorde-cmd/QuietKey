//! M29 HOST-only owner for four manual-keypad dice transcripts.
//!
//! This fixed-memory seam joins the P0.1 logical keypad to the unchanged
//! `qk-provisioning` dice validator and the M27 borrow-only ceremony screens.
//! It is not a renderer, physical keypad driver, entropy source, or target
//! cleanup claim.

use crate::screen_flow::{
    CeremonyPurpose, EntropyInputMode, FlowApplyOutcome, FlowEvent, FlowKind, FlowTerminal,
    KeypadKey, Screen, ScreenFlow, ScreenKind, WipingReason,
};
use qk_provisioning::{HostProvisioningRun, ProvisioningError};

pub const MANUAL_TRANSCRIPT_BYTES: usize = 100;
const PURPOSE_COUNT: usize = 4;

struct SecretTranscript {
    bytes: Box<[u8; MANUAL_TRANSCRIPT_BYTES]>,
    len: usize,
}

impl SecretTranscript {
    fn empty() -> Self {
        Self {
            bytes: Box::new([0; MANUAL_TRANSCRIPT_BYTES]),
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

impl Drop for SecretTranscript {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualKeypadError {
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

impl ManualKeypadError {
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

impl core::fmt::Display for ManualKeypadError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for ManualKeypadError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualKeypadEvent {
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
pub struct ManualTranscriptView<'a> {
    bytes: &'a [u8],
}

impl<'a> ManualTranscriptView<'a> {
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

#[derive(Clone, Copy)]
pub enum ManualKeypadScreen<'a> {
    Entry {
        purpose: CeremonyPurpose,
        count: usize,
    },
    Echo {
        purpose: CeremonyPurpose,
        transcript: ManualTranscriptView<'a>,
    },
    Confirm {
        purpose: CeremonyPurpose,
        transcript: ManualTranscriptView<'a>,
    },
    AwaitingCommitment {
        purpose: CeremonyPurpose,
    },
    Commitment {
        purpose: CeremonyPurpose,
        commitment: [u8; 32],
    },
    Complete,
    Failed(ManualKeypadError),
}

pub enum ManualKeypadOutcome {
    Continue,
    ProvisioningReady(Box<HostProvisioningRun>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EntryStage {
    Entry,
    Echo,
    Confirm,
    AwaitingCommitment,
    Commitment,
    Complete,
    Failed(ManualKeypadError),
}

/// Owning M29 manual-entry scope.
///
/// This owner deliberately implements no `Clone`, `Copy`, `Debug`, or
/// display trait and offers no method that returns an owned transcript.
pub struct ManualKeypadSession {
    flow: Option<ScreenFlow>,
    transcripts: [SecretTranscript; PURPOSE_COUNT],
    purpose_index: usize,
    stage: EntryStage,
}

impl ManualKeypadSession {
    /// Bind to an M27 provisioning flow already positioned at manual-keypad
    /// ceremony input. A mismatched flow is terminated rather than widened.
    pub fn begin(mut flow: ScreenFlow) -> Result<Self, ManualKeypadError> {
        let valid = flow.flow_kind() == FlowKind::Provisioning
            && matches!(
                flow.screen(),
                Some(Screen::CeremonyInput {
                    purpose: CeremonyPurpose::SeedA,
                    mode: EntropyInputMode::ManualKeypad,
                })
            );
        if !valid {
            flow.terminate_manual_keypad(WipingReason::InvalidTransition);
            return Err(ManualKeypadError::InvalidTransition);
        }
        Ok(Self {
            flow: Some(flow),
            transcripts: core::array::from_fn(|_| SecretTranscript::empty()),
            purpose_index: 0,
            stage: EntryStage::Entry,
        })
    }

    #[must_use]
    pub fn screen(&self) -> ManualKeypadScreen<'_> {
        let Some(purpose) = purpose_at(self.purpose_index) else {
            return ManualKeypadScreen::Failed(ManualKeypadError::InvalidTransition);
        };
        let transcript = ManualTranscriptView {
            bytes: self.transcripts[self.purpose_index].as_slice(),
        };
        match self.stage {
            EntryStage::Entry => ManualKeypadScreen::Entry {
                purpose,
                count: self.transcripts[self.purpose_index].len,
            },
            EntryStage::Echo => ManualKeypadScreen::Echo {
                purpose,
                transcript,
            },
            EntryStage::Confirm => ManualKeypadScreen::Confirm {
                purpose,
                transcript,
            },
            EntryStage::AwaitingCommitment => ManualKeypadScreen::AwaitingCommitment { purpose },
            EntryStage::Commitment => {
                let commitment = match self.flow.as_ref().and_then(ScreenFlow::screen) {
                    Some(Screen::CeremonyCommitment {
                        commitment: view, ..
                    }) => *view.bytes(),
                    _ => return ManualKeypadScreen::Failed(ManualKeypadError::InvalidTransition),
                };
                ManualKeypadScreen::Commitment {
                    purpose,
                    commitment,
                }
            }
            EntryStage::Complete => ManualKeypadScreen::Complete,
            EntryStage::Failed(error) => ManualKeypadScreen::Failed(error),
        }
    }

    #[must_use]
    pub fn retained_counts(&self) -> [usize; PURPOSE_COUNT] {
        core::array::from_fn(|index| self.transcripts[index].len)
    }

    #[must_use]
    pub fn terminal(&self) -> Option<FlowTerminal> {
        self.flow.as_ref().and_then(ScreenFlow::terminal)
    }

    /// Apply one closed manual-entry event. The four recoverable input errors
    /// return `Err` without changing the current stage, count, or bytes.
    pub fn apply(
        &mut self,
        event: ManualKeypadEvent,
    ) -> Result<ManualKeypadOutcome, ManualKeypadError> {
        if matches!(self.stage, EntryStage::Complete | EntryStage::Failed(_)) {
            return Err(ManualKeypadError::Finished);
        }
        if let Some((error, reason)) = interruption(event) {
            self.fail(error, reason);
            return Err(error);
        }

        match (self.stage, event) {
            (EntryStage::Entry, ManualKeypadEvent::Key(key)) => self.apply_entry_key(key),
            (EntryStage::Echo, ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                if !self.flow_mut()?.confirm_manual_keypad_echo() {
                    self.fail(
                        ManualKeypadError::InvalidTransition,
                        WipingReason::InvalidTransition,
                    );
                    return Err(ManualKeypadError::InvalidTransition);
                }
                self.stage = EntryStage::Confirm;
                Ok(ManualKeypadOutcome::Continue)
            }
            (EntryStage::Confirm, ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                if !self.flow_mut()?.complete_manual_keypad_confirmation() {
                    self.fail(
                        ManualKeypadError::InvalidTransition,
                        WipingReason::InvalidTransition,
                    );
                    return Err(ManualKeypadError::InvalidTransition);
                }
                self.stage = EntryStage::AwaitingCommitment;
                Ok(ManualKeypadOutcome::Continue)
            }
            (EntryStage::AwaitingCommitment, ManualKeypadEvent::CommitmentReady(commitment)) => {
                let reached = self.apply_root_kind(FlowEvent::CeremonyCommitmentReady(commitment));
                if reached != Some(ScreenKind::CeremonyCommitment) {
                    self.fail(
                        ManualKeypadError::InvalidTransition,
                        WipingReason::InvalidTransition,
                    );
                    return Err(ManualKeypadError::InvalidTransition);
                }
                self.stage = EntryStage::Commitment;
                Ok(ManualKeypadOutcome::Continue)
            }
            (EntryStage::Commitment, ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.finish_commitment()
            }
            (_, ManualKeypadEvent::Key(KeypadKey::CancelBack)) => {
                self.fail(ManualKeypadError::Cancelled, WipingReason::Cancelled);
                Err(ManualKeypadError::Cancelled)
            }
            _ => {
                self.fail(
                    ManualKeypadError::InvalidTransition,
                    WipingReason::InvalidTransition,
                );
                Err(ManualKeypadError::InvalidTransition)
            }
        }
    }

    /// Recover the M27 flow only after successful four-purpose completion.
    pub fn take_completed_flow(&mut self) -> Option<ScreenFlow> {
        if self.stage == EntryStage::Complete {
            self.flow.take()
        } else {
            None
        }
    }

    fn apply_entry_key(
        &mut self,
        key: KeypadKey,
    ) -> Result<ManualKeypadOutcome, ManualKeypadError> {
        let transcript = &mut self.transcripts[self.purpose_index];
        match key {
            KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::FourLeft
            | KeypadKey::Five
            | KeypadKey::SixRight => {
                if transcript.len == MANUAL_TRANSCRIPT_BYTES {
                    return Err(ManualKeypadError::TranscriptFull);
                }
                let Some(face) = face_byte(key) else {
                    return Err(ManualKeypadError::InvalidFaceKey);
                };
                transcript.push(face);
            }
            KeypadKey::CeDelete => {
                if transcript.len == 0 {
                    return Err(ManualKeypadError::EmptyDelete);
                }
                transcript.delete();
            }
            KeypadKey::EqualsConfirmEnter => {
                if transcript.len != MANUAL_TRANSCRIPT_BYTES {
                    return Err(ManualKeypadError::TranscriptCountIncomplete);
                }
                if !self
                    .flow
                    .as_mut()
                    .is_some_and(ScreenFlow::begin_manual_keypad_echo)
                {
                    self.fail(
                        ManualKeypadError::InvalidTransition,
                        WipingReason::InvalidTransition,
                    );
                    return Err(ManualKeypadError::InvalidTransition);
                }
                self.stage = EntryStage::Echo;
            }
            KeypadKey::CancelBack => {
                self.fail(ManualKeypadError::Cancelled, WipingReason::Cancelled);
                return Err(ManualKeypadError::Cancelled);
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
            | KeypadKey::Percent => return Err(ManualKeypadError::InvalidFaceKey),
        }
        Ok(ManualKeypadOutcome::Continue)
    }

    fn finish_commitment(&mut self) -> Result<ManualKeypadOutcome, ManualKeypadError> {
        let expected = if self.purpose_index + 1 == PURPOSE_COUNT {
            ScreenKind::DerivationExplanation
        } else {
            ScreenKind::CeremonyInput
        };
        let reached = self.apply_root_kind(FlowEvent::Key(KeypadKey::EqualsConfirmEnter));
        if reached != Some(expected) {
            self.fail(
                ManualKeypadError::InvalidTransition,
                WipingReason::InvalidTransition,
            );
            return Err(ManualKeypadError::InvalidTransition);
        }

        if self.purpose_index + 1 != PURPOSE_COUNT {
            self.purpose_index += 1;
            self.stage = EntryStage::Entry;
            return Ok(ManualKeypadOutcome::Continue);
        }

        let transcripts = [
            self.transcripts[0].as_slice(),
            self.transcripts[1].as_slice(),
            self.transcripts[2].as_slice(),
            self.transcripts[3].as_slice(),
        ];
        match HostProvisioningRun::from_dice(transcripts) {
            Ok(run) => {
                self.wipe_transcripts();
                self.stage = EntryStage::Complete;
                Ok(ManualKeypadOutcome::ProvisioningReady(Box::new(run)))
            }
            Err(ProvisioningError::TranscriptReuse) => {
                self.fail(
                    ManualKeypadError::TranscriptReuse,
                    WipingReason::OperationFailed,
                );
                Err(ManualKeypadError::TranscriptReuse)
            }
            Err(error) => {
                let result = ManualKeypadError::ProvisioningRejected(error);
                self.fail(result, WipingReason::OperationFailed);
                Err(result)
            }
        }
    }

    fn flow_mut(&mut self) -> Result<&mut ScreenFlow, ManualKeypadError> {
        self.flow.as_mut().ok_or(ManualKeypadError::Finished)
    }

    /// Collapse M27's scoped outcome to a copy before any later owner access.
    fn apply_root_kind(&mut self, event: FlowEvent<'static>) -> Option<ScreenKind> {
        let flow = self.flow.as_mut()?;
        match flow.apply(event).ok()? {
            FlowApplyOutcome::Continue(kind) => Some(kind),
            _ => None,
        }
    }

    fn fail(&mut self, error: ManualKeypadError, reason: WipingReason) {
        self.wipe_transcripts();
        if let Some(flow) = self.flow.as_mut() {
            flow.terminate_manual_keypad(reason);
        }
        self.stage = EntryStage::Failed(error);
    }

    fn wipe_transcripts(&mut self) {
        for transcript in &mut self.transcripts {
            transcript.wipe();
        }
    }
}

impl Drop for ManualKeypadSession {
    fn drop(&mut self) {
        self.wipe_transcripts();
        if !matches!(self.stage, EntryStage::Complete | EntryStage::Failed(_)) {
            if let Some(flow) = self.flow.as_mut() {
                flow.terminate_manual_keypad(WipingReason::Cancelled);
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

const fn purpose_at(index: usize) -> Option<CeremonyPurpose> {
    Some(match index {
        0 => CeremonyPurpose::SeedA,
        1 => CeremonyPurpose::SignerB,
        2 => CeremonyPurpose::SignerC,
        3 => CeremonyPurpose::A2,
        _ => return None,
    })
}

fn interruption(event: ManualKeypadEvent) -> Option<(ManualKeypadError, WipingReason)> {
    Some(match event {
        ManualKeypadEvent::OperationFailed => (
            ManualKeypadError::OperationFailed,
            WipingReason::OperationFailed,
        ),
        ManualKeypadEvent::MediaRemoved => {
            (ManualKeypadError::MediaRemoved, WipingReason::MediaRemoved)
        }
        ManualKeypadEvent::CardRemoved => {
            (ManualKeypadError::CardRemoved, WipingReason::CardRemoved)
        }
        ManualKeypadEvent::SessionTimeout => (
            ManualKeypadError::SessionTimeout,
            WipingReason::SessionTimeout,
        ),
        ManualKeypadEvent::Shutdown => (ManualKeypadError::Shutdown, WipingReason::Shutdown),
        ManualKeypadEvent::Restart => (ManualKeypadError::Restart, WipingReason::Restart),
        ManualKeypadEvent::PowerLoss => (ManualKeypadError::PowerLoss, WipingReason::PowerLoss),
        ManualKeypadEvent::Key(_) | ManualKeypadEvent::CommitmentReady(_) => return None,
    })
}

/// Established qk-a1 HOST cleanup shape: force a visible post-fill borrow at
/// a non-inlined boundary so the compiler may not discard the clearing store.
#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}
