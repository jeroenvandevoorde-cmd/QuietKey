//! HOST-only, mode-locked v2 Kit-share intake for qk-core.
//!
//! Scanner mode accepts one already-decoded 142-byte hostile candidate at a
//! time. Fallback mode accepts only the exact P0.1 coordinate sequence for one
//! 228-symbol share. The selected door and representation are immutable. Only
//! qk-kit authenticates frames and releases an opaque combined payload owner.

use crate::capability::{CoreScreen, KeypadKey};
use crate::error::Interruption;
use crate::io_wire::Source;
use crate::session::{CoreSession, HostileIngress};
use crate::wipe::{self, WipingArray};
use core::fmt;
use qk_kit::{
    combine_frames, decode_fallback, frame_metadata, FrameMetadata, KitError, RecoveredKitPayload,
    ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN,
};

/// Exact semantic fallback table. This makes no pixel-layout claim.
pub const KIT_FALLBACK_TABLE_V2: [[u8; 8]; 4] =
    [*b"23456789", *b"abcdefgh", *b"ijkmnpqr", *b"stuvwxyz"];

const FALLBACK_LINE_SYMBOLS: usize = 57;
const FRAME_CHECKSUM_BYTES: usize = 8;
const FRAME_CHECKSUM_OFFSET: usize = 134;

const _: () = assert!(FRAME_LEN == 142);
const _: () = assert!(FALLBACK_SYMBOLS == 228);
const _: () = assert!(FRAME_CHECKSUM_OFFSET + FRAME_CHECKSUM_BYTES == FRAME_LEN);

/// Exact user-selected Kit operation, fixed before either share is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitDoorV2 {
    KitRestore,
    KitSpend,
}

/// Exact user-selected Kit representation, fixed for both share pages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitInputModeV2 {
    Scanner,
    Fallback,
}

/// Exact share page currently expected by the intake owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitShareOrdinalV2 {
    One,
    Two,
}

/// Representations and operations that are foreign at either share screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitForeignInputV2 {
    Image,
    Camera,
    A1,
    Psbt,
    BbqrTransaction,
    Coordinator,
    Transport,
    GenericIntake,
    QrWrapper,
    ModeSelection,
    Other,
}

/// Closed, named Kit-intake rejection surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitIntakeErrorV2 {
    InvalidTransition,
    KitScannerModeMismatch,
    WrongIngressSource,
    DoorSwitchAttempt,
    InvalidFallbackRow,
    InvalidFallbackColumn,
    FallbackEmptyDelete,
    FallbackIncomplete,
    FallbackPendingCoordinate,
    FallbackFull,
    Codec(KitError),
    Interrupted(Interruption),
    Finished,
}

impl KitIntakeErrorV2 {
    /// Stable non-hostile name used by headless and fuzz oracles.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidTransition => "InvalidTransition",
            Self::KitScannerModeMismatch => "KitScannerModeMismatch",
            Self::WrongIngressSource => "WrongIngressSource",
            Self::DoorSwitchAttempt => "DoorSwitchAttempt",
            Self::InvalidFallbackRow => "InvalidFallbackRow",
            Self::InvalidFallbackColumn => "InvalidFallbackColumn",
            Self::FallbackEmptyDelete => "FallbackEmptyDelete",
            Self::FallbackIncomplete => "FallbackIncomplete",
            Self::FallbackPendingCoordinate => "FallbackPendingCoordinate",
            Self::FallbackFull => "FallbackFull",
            Self::Codec(error) => match error {
                KitError::FrameLength => "FrameLength",
                KitError::FrameChecksum => "FrameChecksum",
                KitError::InvalidMagic => "InvalidMagic",
                KitError::UnsupportedVersion => "UnsupportedVersion",
                KitError::InvalidShareIndex => "InvalidShareIndex",
                KitError::FallbackLength => "FallbackLength",
                KitError::MalformedSymbol => "MalformedSymbol",
                KitError::NonCanonicalPadding => "NonCanonicalPadding",
                KitError::DuplicateShare => "DuplicateShare",
                KitError::SameShareIndex => "SameShareIndex",
                KitError::WalletMismatch => "WalletMismatch",
            },
            Self::Interrupted(interruption) => interruption.name(),
            Self::Finished => "Finished",
        }
    }
}

impl fmt::Display for KitIntakeErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitIntakeErrorV2 {}

/// Public non-secret identity for one authenticated canonical frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitFrameIdentityV2 {
    share_index: ShareIndex,
    wallet_id: [u8; 32],
    checksum: [u8; FRAME_CHECKSUM_BYTES],
}

impl KitFrameIdentityV2 {
    #[must_use]
    pub const fn share_index(self) -> ShareIndex {
        self.share_index
    }

    #[must_use]
    pub const fn wallet_id(self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn checksum(self) -> [u8; FRAME_CHECKSUM_BYTES] {
        self.checksum
    }
}

/// Non-secret fallback-entry progress for the current share page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitFallbackProgressV2 {
    committed_symbols: usize,
    pending_row: Option<u8>,
    next_line: Option<u8>,
    next_column: Option<u8>,
}

impl KitFallbackProgressV2 {
    #[must_use]
    pub const fn committed_symbols(self) -> usize {
        self.committed_symbols
    }

    #[must_use]
    pub const fn pending_row(self) -> Option<u8> {
        self.pending_row
    }

    #[must_use]
    pub const fn next_line(self) -> Option<u8> {
        self.next_line
    }

    #[must_use]
    pub const fn next_column(self) -> Option<u8> {
        self.next_column
    }
}

/// Typed non-secret display facts for one Kit share screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitIntakeScreenV2 {
    door: KitDoorV2,
    mode: KitInputModeV2,
    page: KitShareOrdinalV2,
    fallback: KitFallbackProgressV2,
}

impl KitIntakeScreenV2 {
    #[must_use]
    pub const fn door(self) -> KitDoorV2 {
        self.door
    }

    #[must_use]
    pub const fn mode(self) -> KitInputModeV2 {
        self.mode
    }

    #[must_use]
    pub const fn page(self) -> KitShareOrdinalV2 {
        self.page
    }

    #[must_use]
    pub const fn fallback(self) -> KitFallbackProgressV2 {
        self.fallback
    }

    #[must_use]
    pub const fn fallback_table(self) -> &'static [[u8; 8]; 4] {
        &KIT_FALLBACK_TABLE_V2
    }
}

/// Result of one accepted Kit-intake event.
#[allow(clippy::large_enum_variant)]
pub enum KitIntakeOutcomeV2 {
    Continue(KitIntakeScreenV2),
    FirstShareAccepted(KitIntakeScreenV2),
    Ready(KitIntakeReadyV2),
}

/// Opaque same-wallet, opposite-index Kit capability.
///
/// This owner deliberately exposes no recovered-payload accessor.
pub struct KitIntakeReadyV2 {
    payload: RecoveredKitPayload,
    session_identity: Option<WipingArray<16>>,
    door: KitDoorV2,
    mode: KitInputModeV2,
    wallet_id: [u8; 32],
    identities: [KitFrameIdentityV2; 2],
}

pub(crate) struct KitIntakeRestorePartsV2 {
    pub(crate) payload: RecoveredKitPayload,
    pub(crate) session_identity: Option<WipingArray<16>>,
    pub(crate) door: KitDoorV2,
    pub(crate) mode: KitInputModeV2,
    pub(crate) wallet_id: [u8; 32],
    pub(crate) identities: [KitFrameIdentityV2; 2],
}

pub(crate) struct KitIntakeSpendPartsV2 {
    pub(crate) payload: RecoveredKitPayload,
    pub(crate) session_identity: Option<WipingArray<16>>,
    pub(crate) door: KitDoorV2,
    pub(crate) mode: KitInputModeV2,
    pub(crate) wallet_id: [u8; 32],
    pub(crate) identities: [KitFrameIdentityV2; 2],
}

impl KitIntakeReadyV2 {
    #[must_use]
    pub const fn door(&self) -> KitDoorV2 {
        self.door
    }

    #[must_use]
    pub const fn mode(&self) -> KitInputModeV2 {
        self.mode
    }

    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn frame_identities(&self) -> [KitFrameIdentityV2; 2] {
        self.identities
    }

    pub(crate) fn into_restore_parts(self) -> KitIntakeRestorePartsV2 {
        KitIntakeRestorePartsV2 {
            payload: self.payload,
            session_identity: self.session_identity,
            door: self.door,
            mode: self.mode,
            wallet_id: self.wallet_id,
            identities: self.identities,
        }
    }

    pub(crate) fn into_spend_parts(self) -> KitIntakeSpendPartsV2 {
        KitIntakeSpendPartsV2 {
            payload: self.payload,
            session_identity: self.session_identity,
            door: self.door,
            mode: self.mode,
            wallet_id: self.wallet_id,
            identities: self.identities,
        }
    }
}

struct ScannerCandidateGuard<'a> {
    bytes: &'a mut [u8; FRAME_LEN],
}

impl ScannerCandidateGuard<'_> {
    fn as_array(&self) -> &[u8; FRAME_LEN] {
        self.bytes
    }
}

impl Drop for ScannerCandidateGuard<'_> {
    fn drop(&mut self) {
        wipe::bytes(self.bytes);
    }
}

/// One mode-locked owner spanning exactly two Kit-share screens.
pub struct KitIntakeSessionV2 {
    session_identity: Option<WipingArray<16>>,
    door: KitDoorV2,
    mode: KitInputModeV2,
    page: KitShareOrdinalV2,
    first_frame: WipingArray<FRAME_LEN>,
    first_identity: Option<KitFrameIdentityV2>,
    fallback: WipingArray<FALLBACK_SYMBOLS>,
    fallback_len: usize,
    pending_row: Option<u8>,
    failed: Option<KitIntakeErrorV2>,
    active: bool,
}

impl KitIntakeSessionV2 {
    /// Start one already-confirmed typed door and input-mode pair.
    #[must_use]
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn begin(door: KitDoorV2, mode: KitInputModeV2) -> Self {
        Self::begin_bound(door, mode, None)
    }

    fn begin_bound(
        door: KitDoorV2,
        mode: KitInputModeV2,
        session_identity: Option<[u8; 16]>,
    ) -> Self {
        Self {
            session_identity: session_identity.map(|mut value| WipingArray::take(&mut value)),
            door,
            mode,
            page: KitShareOrdinalV2::One,
            first_frame: WipingArray::zeroed(),
            first_identity: None,
            fallback: WipingArray::zeroed(),
            fallback_len: 0,
            pending_row: None,
            failed: None,
            active: true,
        }
    }

    /// Start the product intake owner on an already-open Kit process session.
    /// The typed door and representation are fixed before the first share
    /// screen, and no capability or process identity leaves `CoreSession`.
    pub fn begin_in_core(
        core: &mut CoreSession,
        door: KitDoorV2,
        mode: KitInputModeV2,
    ) -> Result<Self, KitIntakeErrorV2> {
        let session_identity = match core.begin_kit_intake() {
            Ok(identity) => identity,
            Err(_) => {
                return Err(KitIntakeErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::OperationFailed),
                ))
            }
        };
        let mut session = Self::begin_bound(door, mode, Some(session_identity));
        if core.kit_show(CoreScreen::ScanKitShareOne).is_err() {
            return Err(session.fail(KitIntakeErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(session)
    }

    #[must_use]
    pub fn screen(&self) -> Option<KitIntakeScreenV2> {
        self.active.then(|| self.current_screen())
    }

    #[must_use]
    pub const fn failure(&self) -> Option<KitIntakeErrorV2> {
        self.failed
    }

    /// Consume one exact scanner candidate and clear the caller's bytes on
    /// success, rejection, finished-session use, or unwind.
    fn submit_scanner_frame_bound(
        &mut self,
        frame: &mut [u8; FRAME_LEN],
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let candidate = ScannerCandidateGuard { bytes: frame };
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        if self.mode != KitInputModeV2::Scanner {
            return Err(self.fail(KitIntakeErrorV2::KitScannerModeMismatch));
        }
        self.accept_frame(candidate.as_array())
    }

    /// Semantic scanner transition reserved for the ring-fenced target.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn submit_scanner_frame(
        &mut self,
        frame: &mut [u8; FRAME_LEN],
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.submit_scanner_frame_bound(frame)
    }

    /// Consume one purpose-bound camera candidate without exposing transport
    /// bytes through a public accessor.
    ///
    /// The transport allocation and fixed scratch are cleared on every return
    /// path. Only the exact Kit-camera source and canonical frame width reach
    /// the existing scanner parser.
    fn submit_scanner_ingress_bound(
        &mut self,
        ingress: HostileIngress,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let (source, bytes) = ingress.into_kit_parts();
        if !self.active {
            drop(bytes);
            return Err(KitIntakeErrorV2::Finished);
        }
        if self.mode != KitInputModeV2::Scanner {
            drop(bytes);
            return Err(self.fail(KitIntakeErrorV2::KitScannerModeMismatch));
        }
        if source != Source::CameraKitCandidate {
            drop(bytes);
            return Err(self.fail(KitIntakeErrorV2::WrongIngressSource));
        }
        if bytes.len() != FRAME_LEN {
            drop(bytes);
            return Err(self.fail(KitIntakeErrorV2::Codec(KitError::FrameLength)));
        }
        let mut frame = WipingArray::<FRAME_LEN>::zeroed();
        frame.as_mut_array().copy_from_slice(bytes.as_slice());
        drop(bytes);
        self.submit_scanner_frame_bound(frame.as_mut_array())
    }

    /// Semantic hostile-ingress transition reserved for the ring-fenced target.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn submit_scanner_ingress(
        &mut self,
        ingress: HostileIngress,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.submit_scanner_ingress_bound(ingress)
    }

    /// Consume the one completed source-02 transfer retained by qk-core and
    /// advance only the typed Kit share screens. Transport bytes never cross a
    /// public accessor and every rejection terminates both purpose owners.
    pub fn submit_scanner_from_core(
        &mut self,
        core: &mut CoreSession,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let session_identity = self.require_core_binding(core)?;
        let ingress = match core.take_kit_ingress() {
            Ok(ingress) => ingress,
            Err(_) => {
                return Err(self.fail(KitIntakeErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::OperationFailed),
                )))
            }
        };
        let outcome = match self.submit_scanner_ingress_bound(ingress) {
            Ok(outcome) => outcome,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        self.finish_core_intake(core, &session_identity, &outcome)?;
        if core.kit_show(intake_outcome_screen(&outcome)).is_err() {
            return Err(self.fail(KitIntakeErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(outcome)
    }

    /// Apply one exact logical P0.1 key to the selected fallback screen.
    fn apply_fallback_key_bound(
        &mut self,
        key: KeypadKey,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        if self.mode != KitInputModeV2::Fallback {
            return Err(self.fail(KitIntakeErrorV2::KitScannerModeMismatch));
        }

        match key {
            KeypadKey::CancelBack => {
                Err(self.fail(KitIntakeErrorV2::Interrupted(Interruption::Cancelled)))
            }
            KeypadKey::CeDelete => self.delete_fallback_coordinate(),
            KeypadKey::EqualsConfirmEnter => self.confirm_fallback(),
            _ => self.apply_fallback_coordinate(key),
        }
    }

    /// Semantic fallback-key transition reserved for the ring-fenced target.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn apply_fallback_key(
        &mut self,
        key: KeypadKey,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.apply_fallback_key_bound(key)
    }

    /// Read one fallback coordinate through the sole qk-core keypad grant and
    /// advance the typed share display without exposing the capability.
    pub fn apply_fallback_key_from_core(
        &mut self,
        core: &mut CoreSession,
        key: KeypadKey,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let session_identity = self.require_core_binding(core)?;
        let key = match core.kit_read_key(key) {
            Ok(key) => key,
            Err(_) => {
                return Err(self.fail(KitIntakeErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::CapabilityFailed),
                )))
            }
        };
        let outcome = match self.apply_fallback_key_bound(key) {
            Ok(outcome) => outcome,
            Err(error) => {
                core.terminate_kit(match error {
                    KitIntakeErrorV2::Interrupted(reason) => reason,
                    _ => Interruption::OperationFailed,
                });
                return Err(error);
            }
        };
        self.finish_core_intake(core, &session_identity, &outcome)?;
        if core.kit_show(intake_outcome_screen(&outcome)).is_err() {
            return Err(self.fail(KitIntakeErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(outcome)
    }

    /// Mode is immutable after the typed share flow begins.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn select_mode(
        &mut self,
        _mode: KitInputModeV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(KitIntakeErrorV2::KitScannerModeMismatch))
    }

    /// Terminate the bound process session on any attempted mode change.
    pub fn select_mode_in_core(
        &mut self,
        core: &mut CoreSession,
        _mode: KitInputModeV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.require_core_binding(core)?;
        Err(self.fail_in_core(
            core,
            KitIntakeErrorV2::KitScannerModeMismatch,
            Interruption::OperationFailed,
        ))
    }

    /// Door is immutable after its typed confirmation.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn reselect_door(
        &mut self,
        _door: KitDoorV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(KitIntakeErrorV2::DoorSwitchAttempt))
    }

    /// Terminate the bound process session on any attempted door change.
    pub fn reselect_door_in_core(
        &mut self,
        core: &mut CoreSession,
        _door: KitDoorV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.require_core_binding(core)?;
        Err(self.fail_in_core(
            core,
            KitIntakeErrorV2::DoorSwitchAttempt,
            Interruption::OperationFailed,
        ))
    }

    /// Reject every representation foreign to the selected share screen.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn reject_foreign_input(
        &mut self,
        _input: KitForeignInputV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(KitIntakeErrorV2::KitScannerModeMismatch))
    }

    /// Terminate the bound process session on a foreign representation.
    pub fn reject_foreign_input_in_core(
        &mut self,
        core: &mut CoreSession,
        _input: KitForeignInputV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.require_core_binding(core)?;
        Err(self.fail_in_core(
            core,
            KitIntakeErrorV2::KitScannerModeMismatch,
            Interruption::OperationFailed,
        ))
    }

    /// Every closed interruption family clears and terminates intake.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn interrupt(
        &mut self,
        interruption: Interruption,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(KitIntakeErrorV2::Interrupted(interruption)))
    }

    /// Route one interruption through both the purpose owner and process shell.
    pub fn interrupt_in_core(
        &mut self,
        core: &mut CoreSession,
        interruption: Interruption,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        self.require_core_binding(core)?;
        Err(self.fail_in_core(
            core,
            KitIntakeErrorV2::Interrupted(interruption),
            interruption,
        ))
    }

    fn delete_fallback_coordinate(&mut self) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if self.pending_row.take().is_some() {
            return Ok(KitIntakeOutcomeV2::Continue(self.current_screen()));
        }
        let Some(next_length) = self.fallback_len.checked_sub(1) else {
            return Err(self.fail(KitIntakeErrorV2::FallbackEmptyDelete));
        };
        self.fallback_len = next_length;
        if let Some(byte) = self.fallback.as_mut_array().get_mut(next_length) {
            wipe::bytes(core::slice::from_mut(byte));
        }
        Ok(KitIntakeOutcomeV2::Continue(self.current_screen()))
    }

    fn confirm_fallback(&mut self) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if self.pending_row.is_some() {
            return Err(self.fail(KitIntakeErrorV2::FallbackPendingCoordinate));
        }
        if self.fallback_len != FALLBACK_SYMBOLS {
            return Err(self.fail(KitIntakeErrorV2::FallbackIncomplete));
        }
        let mut decoded = WipingArray::<FRAME_LEN>::zeroed();
        if let Err(error) = decode_fallback(self.fallback.as_array(), decoded.as_mut_array()) {
            return Err(self.fail(KitIntakeErrorV2::Codec(error)));
        }
        self.accept_frame(decoded.as_array())
    }

    fn accept_frame(
        &mut self,
        frame: &[u8; FRAME_LEN],
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let metadata =
            frame_metadata(frame).map_err(|error| self.fail(KitIntakeErrorV2::Codec(error)))?;
        let identity = frame_identity(metadata, frame);

        match self.page {
            KitShareOrdinalV2::One => {
                self.first_frame.as_mut_array().copy_from_slice(frame);
                self.first_identity = Some(identity);
                self.clear_fallback();
                self.page = KitShareOrdinalV2::Two;
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(
                    self.current_screen(),
                ))
            }
            KitShareOrdinalV2::Two => {
                let payload = combine_frames(self.first_frame.as_array(), frame)
                    .map_err(|error| self.fail(KitIntakeErrorV2::Codec(error)))?;
                let Some(first_identity) = self.first_identity else {
                    drop(payload);
                    return Err(self.fail(KitIntakeErrorV2::InvalidTransition));
                };
                self.clear_all();
                self.active = false;
                Ok(KitIntakeOutcomeV2::Ready(KitIntakeReadyV2 {
                    payload,
                    session_identity: self.session_identity.take(),
                    door: self.door,
                    mode: self.mode,
                    wallet_id: metadata.wallet_id,
                    identities: [first_identity, identity],
                }))
            }
        }
    }

    fn apply_fallback_coordinate(
        &mut self,
        key: KeypadKey,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let Some(number) = numeric_key(key) else {
            let error = if self.pending_row.is_some() {
                KitIntakeErrorV2::InvalidFallbackColumn
            } else {
                KitIntakeErrorV2::InvalidFallbackRow
            };
            return Err(self.fail(error));
        };

        let Some(row) = self.pending_row else {
            if !(1..=4).contains(&number) {
                return Err(self.fail(KitIntakeErrorV2::InvalidFallbackRow));
            }
            self.pending_row = Some(number);
            return Ok(KitIntakeOutcomeV2::Continue(self.current_screen()));
        };

        if !(1..=8).contains(&number) {
            return Err(self.fail(KitIntakeErrorV2::InvalidFallbackColumn));
        }
        if self.fallback_len == FALLBACK_SYMBOLS {
            return Err(self.fail(KitIntakeErrorV2::FallbackFull));
        }
        let row_index = usize::from(row).checked_sub(1);
        let column_index = usize::from(number).checked_sub(1);
        let symbol = row_index
            .and_then(|row_index| KIT_FALLBACK_TABLE_V2.get(row_index))
            .zip(column_index)
            .and_then(|(symbols, column_index)| symbols.get(column_index))
            .copied();
        let Some(symbol) = symbol else {
            return Err(self.fail(KitIntakeErrorV2::InvalidFallbackColumn));
        };
        let Some(destination) = self.fallback.as_mut_array().get_mut(self.fallback_len) else {
            return Err(self.fail(KitIntakeErrorV2::FallbackFull));
        };
        *destination = symbol;
        let Some(next_length) = self.fallback_len.checked_add(1) else {
            return Err(self.fail(KitIntakeErrorV2::FallbackFull));
        };
        self.fallback_len = next_length;
        self.pending_row = None;
        Ok(KitIntakeOutcomeV2::Continue(self.current_screen()))
    }

    fn current_screen(&self) -> KitIntakeScreenV2 {
        let (next_line, next_column) = if self.fallback_len == FALLBACK_SYMBOLS {
            (None, None)
        } else {
            let line = self
                .fallback_len
                .checked_div(FALLBACK_LINE_SYMBOLS)
                .and_then(|value| value.checked_add(1))
                .and_then(|value| u8::try_from(value).ok());
            let column = self
                .fallback_len
                .checked_rem(FALLBACK_LINE_SYMBOLS)
                .and_then(|value| value.checked_add(1))
                .and_then(|value| u8::try_from(value).ok());
            (line, column)
        };
        KitIntakeScreenV2 {
            door: self.door,
            mode: self.mode,
            page: self.page,
            fallback: KitFallbackProgressV2 {
                committed_symbols: self.fallback_len,
                pending_row: self.pending_row,
                next_line,
                next_column,
            },
        }
    }

    fn fail(&mut self, error: KitIntakeErrorV2) -> KitIntakeErrorV2 {
        drop(self.session_identity.take());
        self.clear_all();
        self.failed = Some(error);
        self.active = false;
        error
    }

    fn fail_in_core(
        &mut self,
        core: &mut CoreSession,
        error: KitIntakeErrorV2,
        reason: Interruption,
    ) -> KitIntakeErrorV2 {
        let error = self.fail(error);
        core.terminate_kit(reason);
        error
    }

    fn clear_fallback(&mut self) {
        wipe::bytes(self.fallback.as_mut_array());
        self.fallback_len = 0;
        self.pending_row = None;
    }

    fn clear_all(&mut self) {
        wipe::bytes(self.first_frame.as_mut_array());
        self.first_identity = None;
        self.clear_fallback();
    }

    fn require_core_binding(
        &mut self,
        core: &mut CoreSession,
    ) -> Result<[u8; 16], KitIntakeErrorV2> {
        let Some(identity) = self.session_identity.as_ref() else {
            core.terminate_kit(Interruption::OperationFailed);
            return Err(self.fail(KitIntakeErrorV2::InvalidTransition));
        };
        if core.require_kit_identity(identity.as_array()).is_err() {
            return Err(self.fail(KitIntakeErrorV2::InvalidTransition));
        }
        Ok(*identity.as_array())
    }

    fn finish_core_intake(
        &mut self,
        core: &mut CoreSession,
        session_identity: &[u8; 16],
        outcome: &KitIntakeOutcomeV2,
    ) -> Result<(), KitIntakeErrorV2> {
        let KitIntakeOutcomeV2::Ready(ready) = outcome else {
            return Ok(());
        };
        if core
            .finish_kit_intake(session_identity, ready.door() == KitDoorV2::KitRestore)
            .is_err()
        {
            return Err(self.fail(KitIntakeErrorV2::InvalidTransition));
        }
        Ok(())
    }
}

impl Drop for KitIntakeSessionV2 {
    fn drop(&mut self) {
        drop(self.session_identity.take());
        self.clear_all();
        self.active = false;
    }
}

fn frame_identity(metadata: FrameMetadata, frame: &[u8; FRAME_LEN]) -> KitFrameIdentityV2 {
    let mut checksum = [0u8; FRAME_CHECKSUM_BYTES];
    let (_, checksum_bytes) = frame.split_at(FRAME_CHECKSUM_OFFSET);
    checksum.copy_from_slice(checksum_bytes);
    KitFrameIdentityV2 {
        share_index: metadata.share_index,
        wallet_id: metadata.wallet_id,
        checksum,
    }
}

const fn numeric_key(key: KeypadKey) -> Option<u8> {
    Some(match key {
        KeypadKey::One => 1,
        KeypadKey::TwoDown => 2,
        KeypadKey::Three => 3,
        KeypadKey::FourLeft => 4,
        KeypadKey::Five => 5,
        KeypadKey::SixRight => 6,
        KeypadKey::Seven => 7,
        KeypadKey::EightUp => 8,
        KeypadKey::Nine => 9,
        KeypadKey::Zero => 0,
        _ => return None,
    })
}

const fn intake_outcome_screen(outcome: &KitIntakeOutcomeV2) -> CoreScreen {
    match outcome {
        KitIntakeOutcomeV2::Continue(screen) => match screen.page {
            KitShareOrdinalV2::One => CoreScreen::ScanKitShareOne,
            KitShareOrdinalV2::Two => CoreScreen::ScanKitShareTwo,
        },
        KitIntakeOutcomeV2::FirstShareAccepted(_) => CoreScreen::ScanKitShareTwo,
        KitIntakeOutcomeV2::Ready(_) => CoreScreen::CombineKitShares,
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::panic)]
mod tests {
    use super::{KitDoorV2, KitInputModeV2, KitIntakeSessionV2, FALLBACK_SYMBOLS, FRAME_LEN};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const OWNED_BYTES: usize = FRAME_LEN + FALLBACK_SYMBOLS;

    #[test]
    fn drop_clears_both_fixed_owners_with_exact_byte_accounting() {
        let session = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
        reset_wiped_bytes();
        drop(session);
        // Explicit session cleanup and each fixed owner's Drop both use the
        // observable wipe boundary.
        assert_eq!(wiped_bytes(), OWNED_BYTES * 2);
    }

    #[test]
    fn caught_unwind_runs_the_same_exact_drop_cleanup() {
        let session = KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Fallback);
        reset_wiped_bytes();
        let outcome = catch_unwind(AssertUnwindSafe(move || {
            let _session = session;
            panic!("test-only caught Kit-intake unwind");
        }));
        assert!(outcome.is_err());
        assert_eq!(wiped_bytes(), OWNED_BYTES * 2);
    }
}
