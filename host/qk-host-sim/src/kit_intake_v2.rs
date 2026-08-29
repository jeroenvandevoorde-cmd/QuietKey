//! V2 slice-9 fixed-memory, mode-locked Kit-share intake.
//!
//! HOST REFERENCE ONLY -- NOT A CAMERA, QR IMAGE DECODER, PHYSICAL KEYPAD,
//! RECOVERY OPERATION, OR TARGET CLAIM. Scanner mode receives one already
//! decoded hostile frame candidate. Fallback mode receives one logical P0.1
//! key at a time. Only qk-kit validates and combines canonical share frames.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::screen_flow::KeypadKey;
use crate::screen_flow_v2::{
    FlowKindV2, FlowTerminalV2, KitDoorV2, ScreenFlowV2, ScreenKindV2, WipingReasonV2,
};
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use qk_kit::{
    combine_frames, decode_fallback, frame_metadata, FrameMetadata, KitError, RecoveredKitPayload,
    ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN,
};

/// Exact semantic fallback table. This is not a pixel or keypad-layout claim.
pub const KIT_FALLBACK_TABLE_V2: [[u8; 8]; 4] =
    [*b"23456789", *b"abcdefgh", *b"ijkmnpqr", *b"stuvwxyz"];

const FALLBACK_LINE_SYMBOLS: usize = 57;
const FALLBACK_LINES: usize = FALLBACK_SYMBOLS / FALLBACK_LINE_SYMBOLS;
const FRAME_CHECKSUM_BYTES: usize = 8;
const FRAME_CHECKSUM_OFFSET: usize = FRAME_LEN - FRAME_CHECKSUM_BYTES;

const _: () = assert!(FRAME_LEN == 142);
const _: () = assert!(FALLBACK_SYMBOLS == 228);
const _: () = assert!(FALLBACK_LINES == 4);

/// Clear share-equivalent fixed-size bytes with observable writes.
#[allow(unsafe_code)]
#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    #[cfg(test)]
    let byte_count = bytes.len();
    for byte in bytes {
        // SAFETY: `byte` is a uniquely borrowed, live byte. The volatile write
        // makes clearing observable to the abstract machine.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

#[cfg(test)]
use core::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    fn as_array(&self) -> &[u8; N] {
        &self.bytes
    }

    fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    fn clear(&mut self) {
        wipe(&mut self.bytes);
    }

    fn copy_from(&mut self, source: &[u8; N]) {
        self.bytes.copy_from_slice(source);
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.clear();
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
        wipe(self.bytes);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitInputModeV2 {
    Scanner,
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitShareOrdinalV2 {
    One,
    Two,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitIntakeInterruptionV2 {
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitIntakeErrorV2 {
    InvalidStart,
    InvalidTransition,
    KitScannerModeMismatch,
    DoorSwitchAttempt,
    InvalidFallbackRow,
    InvalidFallbackColumn,
    FallbackEmptyDelete,
    FallbackIncomplete,
    FallbackPendingCoordinate,
    FallbackFull,
    Codec(KitError),
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
    Finished,
}

impl KitIntakeErrorV2 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidStart => "InvalidStart",
            Self::InvalidTransition => "InvalidTransition",
            Self::KitScannerModeMismatch => "KitScannerModeMismatch",
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
            Self::Cancelled => "Cancelled",
            Self::OperationFailed => "OperationFailed",
            Self::MediaRemoved => "MediaRemoved",
            Self::CardRemoved => "CardRemoved",
            Self::SessionTimeout => "SessionTimeout",
            Self::Shutdown => "Shutdown",
            Self::Restart => "Restart",
            Self::PowerLoss => "PowerLoss",
            Self::Finished => "Finished",
        }
    }
}

impl core::fmt::Display for KitIntakeErrorV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitIntakeErrorV2 {}

/// Public non-secret identity for one accepted canonical frame.
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

// The ready variant deliberately owns fixed-size secret state. Boxing it would
// violate this slice's zero-direct-allocation boundary.
#[allow(clippy::large_enum_variant)]
pub enum KitIntakeOutcomeV2 {
    Continue(KitIntakeScreenV2),
    FirstShareAccepted(KitIntakeScreenV2),
    Ready(KitIntakeReadyV2),
}

/// Opaque same-wallet, opposite-index Kit intake capability.
///
/// This owner deliberately exposes neither its flow nor its recovered payload.
pub struct KitIntakeReadyV2 {
    _flow: ScreenFlowV2,
    _payload: RecoveredKitPayload,
    door: KitDoorV2,
    mode: KitInputModeV2,
    wallet_id: [u8; 32],
    identities: [KitFrameIdentityV2; 2],
    next_screen: ScreenKindV2,
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

    #[must_use]
    pub const fn next_screen(&self) -> ScreenKindV2 {
        self.next_screen
    }
}

/// One mode-locked owner spanning both QK-DEC-126 share screens.
pub struct KitIntakeSessionV2 {
    flow: Option<ScreenFlowV2>,
    door: KitDoorV2,
    mode: KitInputModeV2,
    page: KitShareOrdinalV2,
    first_frame: SecretBytes<FRAME_LEN>,
    first_identity: Option<KitFrameIdentityV2>,
    fallback: SecretBytes<FALLBACK_SYMBOLS>,
    fallback_len: usize,
    pending_row: Option<u8>,
    failed: Option<KitIntakeErrorV2>,
    active: bool,
}

impl KitIntakeSessionV2 {
    pub fn begin(mut flow: ScreenFlowV2, mode: KitInputModeV2) -> Result<Self, KitIntakeErrorV2> {
        let door = flow.selected_kit_door();
        if flow.flow_kind() != FlowKindV2::Kit
            || flow.screen_kind() != Some(ScreenKindV2::ScanKitShareOne)
            || door.is_none()
        {
            flow.terminate_kit_intake(WipingReasonV2::InvalidTransition);
            return Err(KitIntakeErrorV2::InvalidStart);
        }
        Ok(Self {
            flow: Some(flow),
            door: door.expect("checked typed Kit door"),
            mode,
            page: KitShareOrdinalV2::One,
            first_frame: SecretBytes::zeroed(),
            first_identity: None,
            fallback: SecretBytes::zeroed(),
            fallback_len: 0,
            pending_row: None,
            failed: None,
            active: true,
        })
    }

    #[must_use]
    pub fn screen(&self) -> Option<KitIntakeScreenV2> {
        self.active.then(|| self.current_screen())
    }

    #[must_use]
    pub fn terminal(&self) -> Option<FlowTerminalV2> {
        self.flow.as_ref().and_then(ScreenFlowV2::terminal)
    }

    #[must_use]
    pub const fn failure(&self) -> Option<KitIntakeErrorV2> {
        self.failed
    }

    pub fn submit_scanner_frame(
        &mut self,
        frame: &mut [u8; FRAME_LEN],
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let candidate = ScannerCandidateGuard { bytes: frame };
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        if self.mode != KitInputModeV2::Scanner {
            return Err(self.fail(
                KitIntakeErrorV2::KitScannerModeMismatch,
                WipingReasonV2::KitScannerModeMismatch,
            ));
        }
        self.accept_frame(candidate.as_array())
    }

    pub fn apply_fallback_key(
        &mut self,
        key: KeypadKey,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        if self.mode != KitInputModeV2::Fallback {
            return Err(self.fail(
                KitIntakeErrorV2::KitScannerModeMismatch,
                WipingReasonV2::KitScannerModeMismatch,
            ));
        }

        match key {
            KeypadKey::CancelBack => {
                Err(self.fail(KitIntakeErrorV2::Cancelled, WipingReasonV2::Cancelled))
            }
            KeypadKey::CeDelete => {
                if self.pending_row.take().is_some() {
                    return Ok(KitIntakeOutcomeV2::Continue(self.current_screen()));
                }
                if self.fallback_len == 0 {
                    return Err(self.fail(
                        KitIntakeErrorV2::FallbackEmptyDelete,
                        WipingReasonV2::OperationFailed,
                    ));
                }
                self.fallback_len -= 1;
                wipe(&mut self.fallback.as_mut_array()[self.fallback_len..=self.fallback_len]);
                Ok(KitIntakeOutcomeV2::Continue(self.current_screen()))
            }
            KeypadKey::EqualsConfirmEnter => {
                if self.pending_row.is_some() {
                    return Err(self.fail(
                        KitIntakeErrorV2::FallbackPendingCoordinate,
                        WipingReasonV2::OperationFailed,
                    ));
                }
                if self.fallback_len != FALLBACK_SYMBOLS {
                    return Err(self.fail(
                        KitIntakeErrorV2::FallbackIncomplete,
                        WipingReasonV2::OperationFailed,
                    ));
                }
                let mut decoded = SecretBytes::<FRAME_LEN>::zeroed();
                if let Err(error) =
                    decode_fallback(self.fallback.as_array(), decoded.as_mut_array())
                {
                    return Err(self.fail(
                        KitIntakeErrorV2::Codec(error),
                        WipingReasonV2::OperationFailed,
                    ));
                }
                self.accept_frame(decoded.as_array())
            }
            _ => self.apply_fallback_coordinate(key),
        }
    }

    pub fn select_mode(
        &mut self,
        _mode: KitInputModeV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(
            KitIntakeErrorV2::KitScannerModeMismatch,
            WipingReasonV2::KitScannerModeMismatch,
        ))
    }

    pub fn reject_foreign_input(
        &mut self,
        _input: KitForeignInputV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(
            KitIntakeErrorV2::KitScannerModeMismatch,
            WipingReasonV2::KitScannerModeMismatch,
        ))
    }

    pub fn reselect_door(
        &mut self,
        _door: KitDoorV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        Err(self.fail(
            KitIntakeErrorV2::DoorSwitchAttempt,
            WipingReasonV2::DoorSwitchAttempt,
        ))
    }

    pub fn interrupt(
        &mut self,
        event: KitIntakeInterruptionV2,
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        if !self.active {
            return Err(KitIntakeErrorV2::Finished);
        }
        let (error, reason) = match event {
            KitIntakeInterruptionV2::Cancelled => {
                (KitIntakeErrorV2::Cancelled, WipingReasonV2::Cancelled)
            }
            KitIntakeInterruptionV2::OperationFailed => (
                KitIntakeErrorV2::OperationFailed,
                WipingReasonV2::OperationFailed,
            ),
            KitIntakeInterruptionV2::MediaRemoved => {
                (KitIntakeErrorV2::MediaRemoved, WipingReasonV2::MediaRemoved)
            }
            KitIntakeInterruptionV2::CardRemoved => {
                (KitIntakeErrorV2::CardRemoved, WipingReasonV2::CardRemoved)
            }
            KitIntakeInterruptionV2::SessionTimeout => (
                KitIntakeErrorV2::SessionTimeout,
                WipingReasonV2::SessionTimeout,
            ),
            KitIntakeInterruptionV2::Shutdown => {
                (KitIntakeErrorV2::Shutdown, WipingReasonV2::Shutdown)
            }
            KitIntakeInterruptionV2::Restart => {
                (KitIntakeErrorV2::Restart, WipingReasonV2::Restart)
            }
            KitIntakeInterruptionV2::PowerLoss => {
                (KitIntakeErrorV2::PowerLoss, WipingReasonV2::PowerLoss)
            }
        };
        Err(self.fail(error, reason))
    }

    fn accept_frame(
        &mut self,
        frame: &[u8; FRAME_LEN],
    ) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
        let metadata = frame_metadata(frame).map_err(|error| {
            self.fail(
                KitIntakeErrorV2::Codec(error),
                WipingReasonV2::OperationFailed,
            )
        })?;
        let identity = frame_identity(metadata, frame);

        match self.page {
            KitShareOrdinalV2::One => {
                self.first_frame.copy_from(frame);
                self.first_identity = Some(identity);
                if !self
                    .flow
                    .as_mut()
                    .is_some_and(ScreenFlowV2::accept_kit_intake_share)
                {
                    return Err(self.fail(
                        KitIntakeErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    ));
                }
                self.clear_fallback();
                self.page = KitShareOrdinalV2::Two;
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(
                    self.current_screen(),
                ))
            }
            KitShareOrdinalV2::Two => {
                let payload =
                    combine_frames(self.first_frame.as_array(), frame).map_err(|error| {
                        self.fail(
                            KitIntakeErrorV2::Codec(error),
                            WipingReasonV2::OperationFailed,
                        )
                    })?;
                if !self
                    .flow
                    .as_mut()
                    .is_some_and(ScreenFlowV2::accept_kit_intake_share)
                    || !self
                        .flow
                        .as_mut()
                        .is_some_and(ScreenFlowV2::complete_kit_intake)
                {
                    return Err(self.fail(
                        KitIntakeErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    ));
                }
                let first = self.first_identity.ok_or_else(|| {
                    self.fail(
                        KitIntakeErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    )
                })?;
                let next_screen = self
                    .flow
                    .as_ref()
                    .and_then(ScreenFlowV2::screen_kind)
                    .ok_or_else(|| {
                        self.fail(
                            KitIntakeErrorV2::InvalidTransition,
                            WipingReasonV2::InvalidTransition,
                        )
                    })?;
                let flow = self.flow.take().ok_or_else(|| {
                    self.fail(
                        KitIntakeErrorV2::InvalidTransition,
                        WipingReasonV2::InvalidTransition,
                    )
                })?;
                self.clear_all();
                self.active = false;
                Ok(KitIntakeOutcomeV2::Ready(KitIntakeReadyV2 {
                    _flow: flow,
                    _payload: payload,
                    door: self.door,
                    mode: self.mode,
                    wallet_id: metadata.wallet_id,
                    identities: [first, identity],
                    next_screen,
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
            return Err(self.fail(error, WipingReasonV2::OperationFailed));
        };

        let Some(row) = self.pending_row else {
            if !(1..=4).contains(&number) {
                return Err(self.fail(
                    KitIntakeErrorV2::InvalidFallbackRow,
                    WipingReasonV2::OperationFailed,
                ));
            }
            self.pending_row = Some(number);
            return Ok(KitIntakeOutcomeV2::Continue(self.current_screen()));
        };

        if !(1..=8).contains(&number) {
            return Err(self.fail(
                KitIntakeErrorV2::InvalidFallbackColumn,
                WipingReasonV2::OperationFailed,
            ));
        }
        if self.fallback_len == FALLBACK_SYMBOLS {
            return Err(self.fail(
                KitIntakeErrorV2::FallbackFull,
                WipingReasonV2::OperationFailed,
            ));
        }
        self.fallback.as_mut_array()[self.fallback_len] =
            KIT_FALLBACK_TABLE_V2[(row - 1) as usize][(number - 1) as usize];
        self.fallback_len += 1;
        self.pending_row = None;
        Ok(KitIntakeOutcomeV2::Continue(self.current_screen()))
    }

    fn current_screen(&self) -> KitIntakeScreenV2 {
        let (next_line, next_column) = if self.fallback_len == FALLBACK_SYMBOLS {
            (None, None)
        } else {
            (
                Some((self.fallback_len / FALLBACK_LINE_SYMBOLS + 1) as u8),
                Some((self.fallback_len % FALLBACK_LINE_SYMBOLS + 1) as u8),
            )
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

    fn fail(&mut self, error: KitIntakeErrorV2, reason: WipingReasonV2) -> KitIntakeErrorV2 {
        self.clear_all();
        if let Some(flow) = self.flow.as_mut() {
            flow.terminate_kit_intake(reason);
        }
        self.failed = Some(error);
        self.active = false;
        error
    }

    fn clear_fallback(&mut self) {
        self.fallback.clear();
        self.fallback_len = 0;
        self.pending_row = None;
    }

    fn clear_all(&mut self) {
        self.first_frame.clear();
        self.first_identity = None;
        self.clear_fallback();
    }
}

impl Drop for KitIntakeSessionV2 {
    fn drop(&mut self) {
        self.clear_all();
        if self.active {
            if let Some(flow) = self.flow.as_mut() {
                flow.terminate_kit_intake(WipingReasonV2::Cancelled);
            }
            self.active = false;
        }
    }
}

fn frame_identity(metadata: FrameMetadata, frame: &[u8; FRAME_LEN]) -> KitFrameIdentityV2 {
    let mut checksum = [0u8; FRAME_CHECKSUM_BYTES];
    checksum.copy_from_slice(&frame[FRAME_CHECKSUM_OFFSET..]);
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

#[cfg(test)]
mod tests {
    use super::{
        wipe, KitInputModeV2, KitIntakeErrorV2, KitIntakeOutcomeV2, KitIntakeSessionV2,
        ScannerCandidateGuard, SecretBytes, WIPED_BYTES,
    };
    use crate::{
        FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, KeypadKey, KitDoorV2, ScreenFlowV2,
        ScreenKindV2,
    };
    use qk_kit::{encode_frame, ShareIndex};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn reset_wiped_bytes() {
        WIPED_BYTES.with(|count| count.set(0));
    }

    fn wiped_bytes() -> usize {
        WIPED_BYTES.with(Cell::get)
    }

    use core::cell::Cell;

    fn flow_at_share_one() -> ScreenFlowV2 {
        let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
        for (event, expected) in [
            (
                FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
                ScreenKindV2::KitDoorSelection,
            ),
            (
                FlowEventV2::SelectKitDoor(KitDoorV2::KitSpend),
                ScreenKindV2::KitDoorConfirmation,
            ),
            (
                FlowEventV2::ConfirmKitDoor(KitDoorV2::KitSpend),
                ScreenKindV2::ScanKitShareOne,
            ),
        ] {
            assert!(matches!(
                flow.apply(event).unwrap(),
                FlowApplyOutcomeV2::Continue(actual) if actual == expected
            ));
        }
        flow
    }

    #[test]
    fn fixed_secret_owner_wipes_on_drop() {
        reset_wiped_bytes();
        let mut owner = SecretBytes::<17>::zeroed();
        owner.as_mut_array().fill(0x5a);
        drop(owner);
        assert_eq!(wiped_bytes(), 17);
    }

    #[test]
    fn scanner_guard_wipes_during_unwind() {
        reset_wiped_bytes();
        let mut candidate = [0xa5u8; 142];
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = ScannerCandidateGuard {
                bytes: &mut candidate,
            };
            panic!("synthetic unwind");
        }));
        assert!(result.is_err());
        assert_eq!(candidate, [0u8; 142]);
        assert_eq!(wiped_bytes(), 142);
    }

    #[test]
    fn wipe_clears_exact_caller_slice() {
        reset_wiped_bytes();
        let mut bytes = [0x11u8; 19];
        wipe(&mut bytes);
        assert_eq!(bytes, [0u8; 19]);
        assert_eq!(wiped_bytes(), 19);
    }

    #[test]
    fn live_session_drop_wipes_retained_first_frame_and_all_fixed_buffers() {
        let mut session =
            KitIntakeSessionV2::begin(flow_at_share_one(), KitInputModeV2::Scanner).unwrap();
        let expected = encode_frame(ShareIndex::One, &[0x31; 32], &[0x52; 96]);
        let mut candidate = expected;
        assert!(matches!(
            session.submit_scanner_frame(&mut candidate).unwrap(),
            KitIntakeOutcomeV2::FirstShareAccepted(_)
        ));
        assert_eq!(session.first_frame.as_array(), &expected);

        reset_wiped_bytes();
        drop(session);
        assert_eq!(wiped_bytes(), 2 * (142 + 228));
    }

    #[test]
    fn live_fallback_session_wipes_during_unwind() {
        let mut session =
            KitIntakeSessionV2::begin(flow_at_share_one(), KitInputModeV2::Fallback).unwrap();
        session.apply_fallback_key(KeypadKey::One).unwrap();
        session.apply_fallback_key(KeypadKey::One).unwrap();
        assert_eq!(session.fallback.as_array()[0], b'2');

        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _session = session;
            panic!("synthetic session unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 2 * (142 + 228));
    }

    #[test]
    fn named_rejection_clears_retained_fallback_before_return() {
        let mut session =
            KitIntakeSessionV2::begin(flow_at_share_one(), KitInputModeV2::Fallback).unwrap();
        session.apply_fallback_key(KeypadKey::One).unwrap();
        session.apply_fallback_key(KeypadKey::One).unwrap();
        reset_wiped_bytes();
        assert_eq!(
            session.apply_fallback_key(KeypadKey::Nine).err(),
            Some(KitIntakeErrorV2::InvalidFallbackRow)
        );
        assert_eq!(session.first_frame.as_array(), &[0u8; 142]);
        assert_eq!(session.fallback.as_array(), &[0u8; 228]);
        assert_eq!(wiped_bytes(), 142 + 228);
    }
}
