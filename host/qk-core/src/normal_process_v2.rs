//! Pure QK-DEC-156 Normal process controller.
//!
//! The runtime supplies already-framed QKDV events and hostile QKIP bytes.
//! This owner binds the untrusted invocation profile, retains the one move-only
//! card factor, and drives the existing Normal owner without adding a second
//! transaction controller. It has no file-descriptor, socket or logging
//! operation.

use crate::capability::{
    CardPresence, CoreDeviceGrants, KeypadKey, MockCardSlot, MockDisplay, MockKeypad,
    NormalCardBDataV2, NormalCardBSignatureV2,
};
use crate::normal_artifact_v2::NormalProfileV2;
use crate::normal_v2::{
    NormalErrorV2, NormalScreenV2, NormalSessionV2, NormalStageV2, ProcessSignatureRejectionV2,
};
use crate::wipe::WipingArray;
use crate::{CoreOutbound, Interruption, NormalExportActionV2, Source};
use core::fmt;
#[cfg(feature = "host-runtime")]
use qk_device_wire::MessageKind;

const DESCRIPTOR_BYTES: usize = 306;
const WALLET_ID_BYTES: usize = 32;
const ACCOUNT_XPUB_BYTES: usize = 111;
const A2_BYTES: usize = 32;
const SIGNATURE_COUNT_BYTES: usize = 2;
const MIN_DER_BYTES: usize = 8;
const MAX_DER_BYTES: usize = 72;
const MAX_SIGNATURES: usize = 100;
const DISPLAY_STAGE_COUNT: usize = 14;

/// Exact card-binding progress before a Normal session may be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalProcessStageV2 {
    AwaitingProfile,
    AwaitingNormalFactor,
    Normal(NormalStageV2),
    Terminated,
}

/// Closed process-only rejection vocabulary. The established Normal leaf
/// error set remains byte- and API-frozen behind the delegated variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalProcessErrorV2 {
    CardProfileMismatch,
    CardSignatureKeyMismatch,
    CardSignatureHighS,
    Normal(NormalErrorV2),
}

impl NormalProcessErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::CardProfileMismatch => "CardProfileMismatch",
            Self::CardSignatureKeyMismatch => "CardSignatureKeyMismatch",
            Self::CardSignatureHighS => "CardSignatureHighS",
            Self::Normal(error) => error.name(),
        }
    }
}

impl From<NormalErrorV2> for NormalProcessErrorV2 {
    fn from(error: NormalErrorV2) -> Self {
        Self::Normal(error)
    }
}

impl fmt::Display for NormalProcessErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for NormalProcessErrorV2 {}

/// One typed QKDV keypad event after its body grammar has been checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalProcessEventV2 {
    LogicalKey(KeypadKey),
    SelectPsbtSource(Source),
    HoldCompleted,
    SelectSd { caller_nonce: [u8; 16] },
    SelectBbqr { non_final_part_len: u16 },
    CardRemoved,
    SessionTimeout,
}

/// Pure one-use controller for the test-only QKDV card seam.
///
/// This type deliberately implements no Clone, Copy, Debug, Display,
/// serializer, logger, or byte-export trait.
pub struct NormalProcessControllerV2 {
    selected_profile: NormalProfileV2,
    stage: NormalProcessStageV2,
    last_normal_stage: Option<NormalStageV2>,
    pending_display_stages: [Option<NormalStageV2>; DISPLAY_STAGE_COUNT],
    pending_display_cursor: usize,
    pending_display_len: usize,
    last_display_stage: Option<NormalStageV2>,
    session: Option<NormalSessionV2>,
    #[cfg(any(test, feature = "fuzzing"))]
    deterministic_identity: Option<([u8; 12], u32)>,
    terminal_error: Option<NormalProcessErrorV2>,
}

impl NormalProcessControllerV2 {
    /// Parse the exact two-byte child PROFILE argument with no default.
    pub fn start(profile_ascii: &[u8]) -> Result<Self, NormalProcessErrorV2> {
        let selected_profile = parse_profile_ascii(profile_ascii).map_err(Self::normal_error)?;
        Ok(Self {
            selected_profile,
            stage: NormalProcessStageV2::AwaitingProfile,
            last_normal_stage: None,
            pending_display_stages: [None; DISPLAY_STAGE_COUNT],
            pending_display_cursor: 0,
            pending_display_len: 0,
            last_display_stage: None,
            session: None,
            #[cfg(any(test, feature = "fuzzing"))]
            deterministic_identity: None,
            terminal_error: None,
        })
    }

    /// Deterministic public-data constructor for the ring-fenced target.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn fuzz_start(
        profile_ascii: &[u8],
        namespace: [u8; 12],
        last_counter: u32,
    ) -> Result<Self, NormalProcessErrorV2> {
        let mut controller = Self::start(profile_ascii)?;
        controller.deterministic_identity = Some((namespace, last_counter));
        Ok(controller)
    }

    pub const fn selected_profile(&self) -> NormalProfileV2 {
        self.selected_profile
    }

    pub const fn stage(&self) -> NormalProcessStageV2 {
        self.stage
    }

    pub const fn terminal_error(&self) -> Option<NormalProcessErrorV2> {
        self.terminal_error
    }

    /// Last stage reached by the underlying owner, exposed only to the
    /// ring-fenced model oracle so staging failures can be locked exactly.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub const fn fuzz_last_normal_stage(&self) -> Option<NormalStageV2> {
        self.last_normal_stage
    }

    /// Drain the next stage frame selected by the byte-complete process
    /// protocol. Typed profile, review and result screens never appear here.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn fuzz_take_display_stage(&mut self) -> Option<NormalStageV2> {
        self.take_display_stage()
    }

    pub fn screen(&self) -> Option<NormalScreenV2<'_>> {
        self.session.as_ref().and_then(NormalSessionV2::screen)
    }

    /// Bind the card-served profile fact before any Normal owner exists.
    pub fn accept_profile(&mut self, profile_wire: u8) -> Result<(), NormalProcessErrorV2> {
        self.require_stage(NormalProcessStageV2::AwaitingProfile)?;
        let card_profile = profile_from_wire(profile_wire)
            .map_err(|error| self.fail(Self::normal_error(error)))?;
        if card_profile != self.selected_profile {
            return Err(self.fail(NormalProcessErrorV2::CardProfileMismatch));
        }
        self.stage = NormalProcessStageV2::AwaitingNormalFactor;
        Ok(())
    }

    /// Parse one complete NormalFactor body and construct the existing Normal
    /// owner. The returned QKIP frame is its sole session-open request.
    pub fn accept_normal_factor(
        &mut self,
        body: &[u8],
    ) -> Result<CoreOutbound, NormalProcessErrorV2> {
        self.require_stage(NormalProcessStageV2::AwaitingNormalFactor)?;
        let card =
            parse_normal_factor(body).map_err(|error| self.fail(Self::normal_error(error)))?;
        let grants = CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::with_normal_data(CardPresence::Present, card)),
            false,
        )
        .map_err(|error| self.fail(Self::normal_error(NormalErrorV2::Core(error))))?;
        let profile = [profile_wire(self.selected_profile)];
        #[cfg(any(test, feature = "fuzzing"))]
        let started = match self.deterministic_identity.take() {
            Some((namespace, last_counter)) => {
                NormalSessionV2::fuzz_start(namespace, last_counter, &profile, grants)
            }
            None => NormalSessionV2::start(&profile, grants),
        };
        #[cfg(not(any(test, feature = "fuzzing")))]
        let started = NormalSessionV2::start(&profile, grants);
        let (session, opening) = started.map_err(|error| self.fail(Self::normal_error(error)))?;
        self.last_normal_stage = Some(session.stage());
        self.stage = NormalProcessStageV2::Normal(session.stage());
        self.session = Some(session);
        self.capture_session_trace();
        Ok(opening)
    }

    /// Map the test-only card rejection without retaining its request bytes.
    pub fn reject_card(&mut self, request_kind: u8, status: u16) -> NormalProcessErrorV2 {
        let error = match (request_kind, status) {
            (0x01 | 0x02, 0x0001) => NormalErrorV2::CardAbsent,
            (0x01 | 0x02, 0x0002 | 0x0003) => NormalErrorV2::CardDataRejected,
            _ => NormalErrorV2::CardDataRejected,
        };
        self.fail(Self::normal_error(error))
    }

    /// Consume hostile QKIP bytes through the existing Normal owner.
    pub fn receive_qkip(
        &mut self,
        bytes: &[u8],
        ancillary_present: bool,
    ) -> Result<Option<CoreOutbound>, NormalProcessErrorV2> {
        self.require_normal()?;
        let result = self
            .session
            .as_mut()
            .ok_or(NormalErrorV2::InvalidTransition)?
            .receive(bytes, ancillary_present);
        match result {
            Ok(outcome) => {
                self.capture_session_trace();
                self.last_normal_stage = Some(outcome.stage());
                self.stage = NormalProcessStageV2::Normal(outcome.stage());
                Ok(outcome.into_outbound())
            }
            Err(error) => Err(self.latch_session_error(error)),
        }
    }

    /// Run the only two controller-owned automatic bridges after an ingress:
    /// consume the retained factor then open A1 intake, or validate A1 and
    /// enter the immutable review.
    pub fn advance_automatic(&mut self) -> Result<Option<CoreOutbound>, NormalProcessErrorV2> {
        self.require_normal()?;
        let stage = self.normal_stage()?;
        let result = match stage {
            NormalStageV2::FactorB => self.apply_session(|session| {
                session.accept_card_b()?;
                session.begin_a1_intake()
            }),
            NormalStageV2::FactorA1 => self.apply_session(NormalSessionV2::validate),
            _ => Err(NormalErrorV2::InvalidTransition),
        };
        self.accept_progress(result)
    }

    /// Apply one body-validated keypad event to the exact current Normal
    /// stage. Every mismatch terminates through the existing owner.
    pub fn handle_event(
        &mut self,
        event: NormalProcessEventV2,
    ) -> Result<Option<CoreOutbound>, NormalProcessErrorV2> {
        self.require_normal()?;
        if let NormalProcessEventV2::CardRemoved = event {
            return self.interrupt(Interruption::CardRemoved);
        }
        if let NormalProcessEventV2::SessionTimeout = event {
            return self.interrupt(Interruption::SessionTimeout);
        }
        let stage = self.normal_stage()?;
        let result = match (stage, event) {
            (
                NormalStageV2::ProfileBinding,
                NormalProcessEventV2::LogicalKey(KeypadKey::EqualsConfirmEnter),
            ) => self.apply_session(NormalSessionV2::confirm_profile),
            (NormalStageV2::Transport, NormalProcessEventV2::SelectPsbtSource(source)) => {
                self.apply_session(|session| session.begin_psbt_intake(source))
            }
            (
                NormalStageV2::Review,
                NormalProcessEventV2::LogicalKey(KeypadKey::EqualsConfirmEnter),
            ) => self.apply_session(NormalSessionV2::advance_review),
            (NormalStageV2::FinalApproval, NormalProcessEventV2::HoldCompleted) => self
                .apply_session(|session| {
                    let token = session.begin_approval_hold()?;
                    session.complete_approval_hold(token)
                }),
            (
                NormalStageV2::AwaitingExportAction,
                NormalProcessEventV2::SelectSd { caller_nonce },
            ) => self.apply_session(|session| {
                session.choose_export(NormalExportActionV2::Sd { caller_nonce })
            }),
            (
                NormalStageV2::AwaitingExportAction,
                NormalProcessEventV2::SelectBbqr { non_final_part_len },
            ) => self.apply_session(|session| {
                session.choose_export(NormalExportActionV2::Bbqr { non_final_part_len })
            }),
            (
                NormalStageV2::TransactionResult,
                NormalProcessEventV2::LogicalKey(KeypadKey::EqualsConfirmEnter),
            ) => self.apply_session(NormalSessionV2::complete_result),
            (_, NormalProcessEventV2::HoldCompleted) => {
                let error = match self.apply_session(NormalSessionV2::begin_approval_hold) {
                    Ok(_) => NormalErrorV2::ApprovalUnavailable,
                    Err(error) => error,
                };
                return Err(self.latch_session_error(error));
            }
            _ => return Err(self.latch_session_error(NormalErrorV2::InvalidTransition)),
        };
        self.accept_progress(result)
    }

    fn require_stage(
        &mut self,
        expected: NormalProcessStageV2,
    ) -> Result<(), NormalProcessErrorV2> {
        if self.terminal_error.is_some() || self.stage == NormalProcessStageV2::Terminated {
            return Err(self
                .terminal_error
                .unwrap_or(Self::normal_error(NormalErrorV2::Finished)));
        }
        if self.stage != expected {
            return Err(self.fail(Self::normal_error(NormalErrorV2::InvalidTransition)));
        }
        Ok(())
    }

    fn require_normal(&mut self) -> Result<(), NormalProcessErrorV2> {
        if self.terminal_error.is_some() || self.stage == NormalProcessStageV2::Terminated {
            return Err(self
                .terminal_error
                .unwrap_or(Self::normal_error(NormalErrorV2::Finished)));
        }
        if !matches!(self.stage, NormalProcessStageV2::Normal(_)) || self.session.is_none() {
            return Err(self.fail(Self::normal_error(NormalErrorV2::InvalidTransition)));
        }
        Ok(())
    }

    fn normal_stage(&self) -> Result<NormalStageV2, NormalProcessErrorV2> {
        match self.stage {
            NormalProcessStageV2::Normal(stage) => Ok(stage),
            _ => Err(Self::normal_error(NormalErrorV2::InvalidTransition)),
        }
    }

    fn apply_session<T>(
        &mut self,
        action: impl FnOnce(&mut NormalSessionV2) -> Result<T, NormalErrorV2>,
    ) -> Result<T, NormalErrorV2> {
        match self.session.as_mut() {
            Some(session) => action(session),
            None => Err(NormalErrorV2::InvalidTransition),
        }
    }

    fn accept_progress(
        &mut self,
        result: Result<crate::NormalProgressV2, NormalErrorV2>,
    ) -> Result<Option<CoreOutbound>, NormalProcessErrorV2> {
        self.capture_session_trace();
        match result {
            Ok(progress) => {
                self.last_normal_stage = Some(progress.stage());
                self.stage = NormalProcessStageV2::Normal(progress.stage());
                Ok(progress.into_outbound())
            }
            Err(error) => Err(self.latch_session_error(error)),
        }
    }

    fn interrupt(
        &mut self,
        reason: Interruption,
    ) -> Result<Option<CoreOutbound>, NormalProcessErrorV2> {
        let error = match self.apply_session(|session| session.interrupt(reason)) {
            Ok(()) => NormalErrorV2::Interrupted(reason),
            Err(error) => error,
        };
        Err(self.latch_session_error(error))
    }

    fn latch_session_error(&mut self, error: NormalErrorV2) -> NormalProcessErrorV2 {
        self.capture_session_trace();
        self.last_normal_stage = self.session.as_ref().map(NormalSessionV2::stage);
        let process_error = match self
            .session
            .as_mut()
            .and_then(NormalSessionV2::take_process_signature_rejection)
        {
            Some(ProcessSignatureRejectionV2::HighS) => NormalProcessErrorV2::CardSignatureHighS,
            Some(ProcessSignatureRejectionV2::KeyMismatch) => {
                NormalProcessErrorV2::CardSignatureKeyMismatch
            }
            Some(ProcessSignatureRejectionV2::Malformed) | None => Self::normal_error(error),
        };
        self.stage = NormalProcessStageV2::Terminated;
        self.terminal_error = Some(process_error);
        process_error
    }

    fn fail(&mut self, error: NormalProcessErrorV2) -> NormalProcessErrorV2 {
        drop(self.session.take());
        self.stage = NormalProcessStageV2::Terminated;
        self.terminal_error = Some(error);
        error
    }

    const fn normal_error(error: NormalErrorV2) -> NormalProcessErrorV2 {
        NormalProcessErrorV2::Normal(error)
    }

    pub(crate) fn take_display_stage(&mut self) -> Option<NormalStageV2> {
        let stage = self
            .pending_display_stages
            .get_mut(self.pending_display_cursor)
            .and_then(Option::take);
        if stage.is_some() {
            self.pending_display_cursor = self.pending_display_cursor.saturating_add(1);
        }
        if self.pending_display_cursor == self.pending_display_len {
            self.pending_display_cursor = 0;
            self.pending_display_len = 0;
        }
        stage
    }

    #[cfg(feature = "host-runtime")]
    pub(crate) fn peer_lost(&mut self) {
        if self.require_normal().is_ok() {
            let _ = self.interrupt(Interruption::PeerLost);
        } else if self.terminal_error.is_none() {
            self.fail(Self::normal_error(NormalErrorV2::Interrupted(
                Interruption::PeerLost,
            )));
        }
    }

    fn capture_session_trace(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let trace = session.take_process_stage_trace();
        for stage in trace
            .into_iter()
            .flatten()
            .filter(|stage| emitted_stage(*stage))
        {
            if self.last_display_stage == Some(stage) {
                continue;
            }
            let Some(slot) = self
                .pending_display_stages
                .get_mut(self.pending_display_len)
            else {
                continue;
            };
            *slot = Some(stage);
            self.pending_display_len = self.pending_display_len.saturating_add(1);
            self.last_display_stage = Some(stage);
        }
    }
}

const fn emitted_stage(stage: NormalStageV2) -> bool {
    matches!(
        stage,
        NormalStageV2::NormalStart
            | NormalStageV2::Transport
            | NormalStageV2::PsbtIntake
            | NormalStageV2::FactorB
            | NormalStageV2::A1Intake
            | NormalStageV2::FactorA1
            | NormalStageV2::Validation
            | NormalStageV2::ApprovalHeld
            | NormalStageV2::Revalidation
            | NormalStageV2::TerminalASigning
            | NormalStageV2::CardBSigning
            | NormalStageV2::Finalization
            | NormalStageV2::AwaitingExportAction
            | NormalStageV2::CompletedWiped
    )
}

impl Drop for NormalProcessControllerV2 {
    fn drop(&mut self) {
        drop(self.session.take());
        if !matches!(
            self.stage,
            NormalProcessStageV2::Normal(NormalStageV2::CompletedWiped)
        ) {
            self.stage = NormalProcessStageV2::Terminated;
        }
    }
}

#[cfg(feature = "host-runtime")]
pub(crate) fn encode_display_body(
    screen: NormalScreenV2<'_>,
    output: &mut [u8; 180],
) -> Result<(MessageKind, usize), NormalErrorV2> {
    output.fill(0);
    let mut cursor = BodyCursor::new(output);
    let kind = match screen {
        NormalScreenV2::Stage(stage) => {
            cursor.byte(stage_wire(stage))?;
            MessageKind::DisplayStage
        }
        NormalScreenV2::ProfileBinding { profile } => {
            cursor.byte(profile_wire(profile))?;
            MessageKind::DisplayProfile
        }
        NormalScreenV2::ReviewOverview(view) => {
            cursor.byte(0x01)?;
            cursor.byte(profile_wire(view.profile()))?;
            cursor.byte(network_wire(view.network()))?;
            cursor.bytes(&view.wallet_id())?;
            cursor.u32(
                u32::try_from(view.input_count()).map_err(|_| NormalErrorV2::ReviewRejected)?,
            )?;
            cursor.u64(view.total_input_amount())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewArithmetic(view) => {
            cursor.byte(0x02)?;
            cursor.u64(view.total_input_amount())?;
            cursor.u64(view.total_output_amount())?;
            cursor.u64(view.fee())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewRecipient(view) => {
            cursor.byte(0x03)?;
            cursor.u32(view.index())?;
            cursor.u64(view.amount())?;
            cursor.sized_u16(view.script_pubkey())?;
            match view.recipient() {
                crate::NormalRecipientFactV2::External {
                    recipient_type,
                    data,
                } => {
                    cursor.byte(0x01)?;
                    cursor.byte(recipient_wire(recipient_type))?;
                    cursor.sized_u16(data)?;
                }
                crate::NormalRecipientFactV2::SelfTransfer {
                    child_index,
                    witness_program,
                } => {
                    cursor.byte(0x02)?;
                    cursor.u32(child_index)?;
                    cursor.sized_u16(witness_program)?;
                }
            }
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewChange(view) => {
            cursor.byte(0x04)?;
            cursor.u32(view.index())?;
            cursor.u64(view.amount())?;
            cursor.sized_u16(view.script_pubkey())?;
            cursor.u32(view.child_index())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewOpReturn(view) => {
            cursor.byte(0x05)?;
            cursor.u32(view.index())?;
            cursor.u64(view.amount())?;
            cursor.sized_u16(view.script_pubkey())?;
            cursor.sized_u16(view.payload())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewLocktime(view) => {
            cursor.byte(0x06)?;
            cursor.u32(view.locktime())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewSequence(view) => {
            cursor.byte(0x07)?;
            cursor.u32(view.input_index())?;
            cursor.u32(view.sequence())?;
            cursor.byte(match view.direct_rbf() {
                qk_psbt::DirectRbf::NotSignaled => 0,
                qk_psbt::DirectRbf::Signaled => 1,
            })?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewFeePolicy(view) => {
            cursor.byte(0x08)?;
            cursor.bytes(view.identifier())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewFeeFacts(view) => {
            cursor.byte(0x09)?;
            cursor.u64(view.fee())?;
            cursor.u32(view.estimated_vsize())?;
            cursor.u64(view.fee_rate_msat_per_vbyte())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::ReviewWarning(view) => {
            cursor.byte(0x0a)?;
            cursor.byte(view.warning().tag())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::FinalApproval(view) => {
            cursor.byte(0x0b)?;
            cursor.byte(profile_wire(view.profile()))?;
            cursor.bytes(&view.review_hash())?;
            MessageKind::DisplayReview
        }
        NormalScreenV2::TransactionResult(view) => {
            encode_result(view.result(), &mut cursor)?;
            MessageKind::DisplayResult
        }
    };
    Ok((kind, cursor.len()))
}

#[cfg(feature = "host-runtime")]
fn encode_result(
    result: &crate::NormalExportResultV2,
    cursor: &mut BodyCursor<'_>,
) -> Result<(), NormalErrorV2> {
    cursor.byte(profile_wire(result.profile()))?;
    cursor.byte(match result.route() {
        crate::NormalExportRouteV2::Sd => 0x01,
        crate::NormalExportRouteV2::Bbqr => 0x02,
    })?;
    let bitmap = u8::from(result.finalized_psbt().is_some())
        | (u8::from(result.raw_transaction().is_some()) << 1)
        | (u8::from(result.finalized_psbt_sd_receipt().is_some()) << 2)
        | (u8::from(result.raw_transaction_sd_receipt().is_some()) << 3);
    cursor.byte(bitmap)?;
    for fact in [result.finalized_psbt(), result.raw_transaction()]
        .into_iter()
        .flatten()
    {
        cursor.byte(artifact_wire(fact.kind()))?;
        cursor.u32(fact.serialized_len())?;
        cursor.bytes(&fact.sha256())?;
    }
    for receipt in [
        result.finalized_psbt_sd_receipt(),
        result.raw_transaction_sd_receipt(),
    ]
    .into_iter()
    .flatten()
    {
        cursor.byte(artifact_wire(receipt.artifact()))?;
        cursor.u32(receipt.total_len())?;
    }
    cursor.bytes(&result.txid())?;
    cursor.bytes(&result.wtxid())
}

#[cfg(feature = "host-runtime")]
const fn stage_wire(stage: NormalStageV2) -> u8 {
    match stage {
        NormalStageV2::NormalStart => 0x01,
        NormalStageV2::ProfileBinding => 0x02,
        NormalStageV2::Transport => 0x03,
        NormalStageV2::PsbtIntake => 0x04,
        NormalStageV2::FactorB => 0x05,
        NormalStageV2::A1Intake => 0x06,
        NormalStageV2::FactorA1 => 0x07,
        NormalStageV2::Validation => 0x08,
        NormalStageV2::Review => 0x09,
        NormalStageV2::FinalApproval => 0x0a,
        NormalStageV2::ApprovalHeld => 0x0b,
        NormalStageV2::Revalidation => 0x0c,
        NormalStageV2::TerminalASigning => 0x0d,
        NormalStageV2::CardBSigning => 0x0e,
        NormalStageV2::Finalization => 0x0f,
        NormalStageV2::AwaitingExportAction => 0x10,
        NormalStageV2::TransactionResult => 0x11,
        NormalStageV2::CompletedWiped => 0x12,
    }
}

#[cfg(feature = "host-runtime")]
const fn recipient_wire(recipient: qk_psbt::RecipientType) -> u8 {
    match recipient {
        qk_psbt::RecipientType::P2wpkh => 0x01,
        qk_psbt::RecipientType::P2wsh => 0x02,
        qk_psbt::RecipientType::P2tr => 0x03,
        qk_psbt::RecipientType::P2pkh => 0x04,
        qk_psbt::RecipientType::P2sh => 0x05,
        qk_psbt::RecipientType::OpReturn => 0x06,
    }
}

#[cfg(feature = "host-runtime")]
const fn artifact_wire(artifact: crate::NormalArtifactKindV2) -> u8 {
    match artifact {
        crate::NormalArtifactKindV2::FinalizedPsbt => 0x01,
        crate::NormalArtifactKindV2::RawTransaction => 0x02,
    }
}

#[cfg(feature = "host-runtime")]
struct BodyCursor<'a> {
    output: &'a mut [u8],
    offset: usize,
}

#[cfg(feature = "host-runtime")]
impl<'a> BodyCursor<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, offset: 0 }
    }

    const fn len(&self) -> usize {
        self.offset
    }

    fn byte(&mut self, value: u8) -> Result<(), NormalErrorV2> {
        self.bytes(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), NormalErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), NormalErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    fn sized_u16(&mut self, value: &[u8]) -> Result<(), NormalErrorV2> {
        let length = u16::try_from(value.len()).map_err(|_| NormalErrorV2::ReviewRejected)?;
        self.bytes(&length.to_le_bytes())?;
        self.bytes(value)
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), NormalErrorV2> {
        let end = self
            .offset
            .checked_add(value.len())
            .ok_or(NormalErrorV2::ReviewRejected)?;
        let target = self
            .output
            .get_mut(self.offset..end)
            .ok_or(NormalErrorV2::ReviewRejected)?;
        target.copy_from_slice(value);
        self.offset = end;
        Ok(())
    }
}

fn parse_profile_ascii(bytes: &[u8]) -> Result<NormalProfileV2, NormalErrorV2> {
    match bytes {
        [] => Err(NormalErrorV2::ProfileMissing),
        b"01" => Ok(NormalProfileV2::SimpleRecovery),
        b"02" => Ok(NormalProfileV2::Inheritance),
        b"03" => Ok(NormalProfileV2::QuantumShelter),
        [_, _] => Err(NormalErrorV2::ProfileUnknown),
        _ => Err(NormalErrorV2::ProfileMalformed),
    }
}

const fn profile_from_wire(value: u8) -> Result<NormalProfileV2, NormalErrorV2> {
    match value {
        0x01 => Ok(NormalProfileV2::SimpleRecovery),
        0x02 => Ok(NormalProfileV2::Inheritance),
        0x03 => Ok(NormalProfileV2::QuantumShelter),
        _ => Err(NormalErrorV2::CardDataRejected),
    }
}

const fn profile_wire(profile: NormalProfileV2) -> u8 {
    match profile {
        NormalProfileV2::SimpleRecovery => 0x01,
        NormalProfileV2::Inheritance => 0x02,
        NormalProfileV2::QuantumShelter => 0x03,
    }
}

#[cfg(feature = "host-runtime")]
const fn network_wire(network: qk_psbt::ReviewNetwork) -> u8 {
    match network {
        qk_psbt::ReviewNetwork::BitcoinMainnet => 0x01,
    }
}

fn parse_normal_factor(body: &[u8]) -> Result<NormalCardBDataV2, NormalErrorV2> {
    let mut offset = 0usize;
    let receive: [u8; DESCRIPTOR_BYTES] = take(body, &mut offset, DESCRIPTOR_BYTES)?
        .try_into()
        .map_err(|_| NormalErrorV2::CardDataRejected)?;
    let change: [u8; DESCRIPTOR_BYTES] = take(body, &mut offset, DESCRIPTOR_BYTES)?
        .try_into()
        .map_err(|_| NormalErrorV2::CardDataRejected)?;
    let wallet_id: [u8; WALLET_ID_BYTES] = take(body, &mut offset, WALLET_ID_BYTES)?
        .try_into()
        .map_err(|_| NormalErrorV2::CardDataRejected)?;
    let account_xpub: [u8; ACCOUNT_XPUB_BYTES] = take(body, &mut offset, ACCOUNT_XPUB_BYTES)?
        .try_into()
        .map_err(|_| NormalErrorV2::CardDataRejected)?;
    let mut a2 = WipingArray::<A2_BYTES>::zeroed();
    a2.as_mut_array()
        .copy_from_slice(take(body, &mut offset, A2_BYTES)?);
    let count = usize::from(read_u16(take(body, &mut offset, SIGNATURE_COUNT_BYTES)?));
    if count > MAX_SIGNATURES {
        return Err(NormalErrorV2::CardDataRejected);
    }

    let parsed = parse_signatures(body, &mut offset, count);
    let signatures = match parsed {
        Ok(signatures) if offset == body.len() => signatures,
        Ok(signatures) => {
            drop(signatures);
            return Err(NormalErrorV2::CardDataRejected);
        }
        Err(error) => return Err(error),
    };
    NormalCardBDataV2::try_new(
        [receive, change],
        wallet_id,
        account_xpub,
        a2.as_mut_array(),
        signatures,
    )
    .map_err(|_| NormalErrorV2::CardDataRejected)
}

fn parse_signatures(
    body: &[u8],
    offset: &mut usize,
    count: usize,
) -> Result<Vec<NormalCardBSignatureV2>, NormalErrorV2> {
    let mut signatures = Vec::new();
    signatures
        .try_reserve_exact(count)
        .map_err(|_| NormalErrorV2::Core(crate::CoreError::AllocationFailed))?;
    let mut prior = None;
    for _ in 0..count {
        let input_index = read_u32(take(body, offset, 4)?);
        if prior.is_some_and(|prior| input_index <= prior) {
            return Err(NormalErrorV2::CardDataRejected);
        }
        prior = Some(input_index);
        let role_b_pubkey: [u8; 33] = take(body, offset, 33)?
            .try_into()
            .map_err(|_| NormalErrorV2::CardDataRejected)?;
        let der_len = usize::from(
            *take(body, offset, 1)?
                .first()
                .ok_or(NormalErrorV2::CardDataRejected)?,
        );
        if !(MIN_DER_BYTES..=MAX_DER_BYTES).contains(&der_len) {
            return Err(NormalErrorV2::CardDataRejected);
        }
        let der = take(body, offset, der_len)?;
        let mut scratch = WipingArray::<MAX_DER_BYTES>::zeroed();
        let Some(target) = scratch.as_mut_array().get_mut(..der_len) else {
            return Err(NormalErrorV2::CardDataRejected);
        };
        target.copy_from_slice(der);
        let signature = NormalCardBSignatureV2::try_new_bound(input_index, role_b_pubkey, target)
            .map_err(|_| NormalErrorV2::CardDataRejected);
        signatures.push(signature?);
    }
    Ok(signatures)
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], NormalErrorV2> {
    let end = offset
        .checked_add(length)
        .ok_or(NormalErrorV2::CardDataRejected)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(NormalErrorV2::CardDataRejected)?;
    *offset = end;
    Ok(value)
}

fn read_u16(bytes: &[u8]) -> u16 {
    let mut value = [0u8; 2];
    if let Some(source) = bytes.get(..2) {
        value.copy_from_slice(source);
    }
    u16::from_le_bytes(value)
}

fn read_u32(bytes: &[u8]) -> u32 {
    let mut value = [0u8; 4];
    if let Some(source) = bytes.get(..4) {
        value.copy_from_slice(source);
    }
    u32::from_le_bytes(value)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "host-runtime")]
    use super::network_wire;
    use super::{
        parse_normal_factor, parse_profile_ascii, NormalProcessControllerV2, A2_BYTES,
        ACCOUNT_XPUB_BYTES, DESCRIPTOR_BYTES, WALLET_ID_BYTES,
    };
    use crate::normal_v2::{classify_card_signature_der, CardSignatureDerClassV2};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::{NormalErrorV2, NormalProcessErrorV2, NormalProcessStageV2, NormalProfileV2};

    #[test]
    fn exact_ascii_profile_has_no_default_and_card_fact_must_match(
    ) -> Result<(), NormalProcessErrorV2> {
        assert_eq!(parse_profile_ascii(&[]), Err(NormalErrorV2::ProfileMissing));
        assert_eq!(
            parse_profile_ascii(b"1"),
            Err(NormalErrorV2::ProfileMalformed)
        );
        assert_eq!(
            parse_profile_ascii(b"04"),
            Err(NormalErrorV2::ProfileUnknown)
        );
        assert_eq!(
            parse_profile_ascii(b"01"),
            Ok(NormalProfileV2::SimpleRecovery)
        );

        let mut controller = NormalProcessControllerV2::start(b"02")?;
        assert_eq!(controller.stage(), NormalProcessStageV2::AwaitingProfile);
        assert_eq!(
            controller.accept_profile(0x01),
            Err(NormalProcessErrorV2::CardProfileMismatch)
        );
        assert_eq!(controller.stage(), NormalProcessStageV2::Terminated);
        assert_eq!(
            controller.terminal_error(),
            Some(NormalProcessErrorV2::CardProfileMismatch)
        );
        Ok(())
    }

    #[test]
    fn strict_der_classification_names_high_s_separately() {
        let low = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert_eq!(
            classify_card_signature_der(&low),
            CardSignatureDerClassV2::LowS
        );

        let mut high = [0u8; 40];
        high[0..6].copy_from_slice(&[0x30, 0x26, 0x02, 0x01, 0x01, 0x02]);
        high[6] = 0x21;
        high[7] = 0;
        high[8..40].fill(0xff);
        assert_eq!(
            classify_card_signature_der(&high),
            CardSignatureDerClassV2::HighS
        );

        assert_eq!(
            classify_card_signature_der(&[0x30, 0x00]),
            CardSignatureDerClassV2::Malformed
        );
        assert_eq!(
            classify_card_signature_der(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]),
            CardSignatureDerClassV2::Malformed
        );
    }

    #[test]
    #[cfg(feature = "host-runtime")]
    fn display_network_byte_is_selected_from_the_bound_review_fact() {
        assert_eq!(network_wire(qk_psbt::ReviewNetwork::BitcoinMainnet), 0x01);
    }

    #[test]
    fn truncated_signature_count_after_a2_drops_the_fixed_secret_owner() {
        let a2_start = 2 * DESCRIPTOR_BYTES + WALLET_ID_BYTES + ACCOUNT_XPUB_BYTES;
        let mut body = vec![0u8; a2_start + A2_BYTES];
        body[a2_start..].fill(0xa5);
        reset_wiped_bytes();
        assert!(matches!(
            parse_normal_factor(&body),
            Err(NormalErrorV2::CardDataRejected)
        ));
        assert_eq!(wiped_bytes(), A2_BYTES);
    }
}
