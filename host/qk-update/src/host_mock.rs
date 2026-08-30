//! Explicit HOST mock for the privileged installer and dual-slot lifecycle.

use crate::{ReleaseVersion, UpdateError, UpdatePresence, VerifiedPackage, TARGET_PLATFORM};

/// One of the two logical mock firmware slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotId {
    A,
    B,
}

impl SlotId {
    const fn inactive(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Committed mock installer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedInstallerState {
    active_slot: SlotId,
    floor: ReleaseVersion,
    keyset_id: [u8; 32],
    active_image_sha256: [u8; 32],
}

impl CommittedInstallerState {
    /// Construct explicit existing installed facts.
    pub const fn new(
        active_slot: SlotId,
        floor: ReleaseVersion,
        keyset_id: [u8; 32],
        active_image_sha256: [u8; 32],
    ) -> Self {
        Self {
            active_slot,
            floor,
            keyset_id,
            active_image_sha256,
        }
    }

    pub const fn active_slot(&self) -> SlotId {
        self.active_slot
    }

    pub const fn floor(&self) -> ReleaseVersion {
        self.floor
    }

    pub const fn keyset_id(&self) -> [u8; 32] {
        self.keyset_id
    }

    pub const fn active_image_sha256(&self) -> [u8; 32] {
        self.active_image_sha256
    }
}

/// Candidate facts reported by the explicitly mock first boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstBootReport {
    slot: SlotId,
    version: ReleaseVersion,
    firmware_image_sha256: [u8; 32],
    target_keyset_id: [u8; 32],
    confirmed_success: bool,
}

impl FirstBootReport {
    pub const fn new(
        slot: SlotId,
        version: ReleaseVersion,
        firmware_image_sha256: [u8; 32],
        target_keyset_id: [u8; 32],
        confirmed_success: bool,
    ) -> Self {
        Self {
            slot,
            version,
            firmware_image_sha256,
            target_keyset_id,
            confirmed_success,
        }
    }
}

/// Fixed-memory version display emitted on each mock boot attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootVersionDisplay {
    target: [u8; 4],
    version: ReleaseVersion,
    decimal: [u8; 20],
    decimal_start: usize,
}

impl BootVersionDisplay {
    #[allow(clippy::arithmetic_side_effects)]
    fn new(version: ReleaseVersion) -> Self {
        let mut decimal = [0u8; 20];
        let mut start = decimal.len();
        let mut value = version.sequence();
        if value == 0 {
            start = start.saturating_sub(1);
            if let Some(slot) = decimal.get_mut(start) {
                *slot = b'0';
            }
        } else {
            while value != 0 {
                let digit = u8::try_from(value % 10).unwrap_or(0);
                value /= 10;
                start = start.saturating_sub(1);
                if let Some(slot) = decimal.get_mut(start) {
                    *slot = b'0'.saturating_add(digit);
                }
            }
        }
        Self {
            target: TARGET_PLATFORM,
            version,
            decimal,
            decimal_start: start,
        }
    }

    pub const fn target(&self) -> [u8; 4] {
        self.target
    }

    pub const fn version(&self) -> ReleaseVersion {
        self.version
    }

    /// Unsigned base-10 sequence with no leading zeroes.
    pub fn sequence_decimal(&self) -> &str {
        let bytes = self.decimal.get(self.decimal_start..).unwrap_or_default();
        core::str::from_utf8(bytes).unwrap_or("")
    }
}

struct TrialState {
    package: VerifiedPackage,
    slot: SlotId,
    boot_attempted: bool,
    report_verified: bool,
}

/// Explicitly mock privileged installer. It writes no slot and performs no
/// real boot; it only models the ratified state transitions.
pub struct MockPrivilegedInstaller {
    committed: CommittedInstallerState,
    trial: Option<TrialState>,
    force_invalid_slot_decision: bool,
    boot_attempts: u32,
    last_display: Option<BootVersionDisplay>,
}

impl MockPrivilegedInstaller {
    /// Construct a fault-free mock installer.
    pub const fn new(committed: CommittedInstallerState) -> Self {
        Self {
            committed,
            trial: None,
            force_invalid_slot_decision: false,
            boot_attempts: 0,
            last_display: None,
        }
    }

    /// Construct the single invalid-slot fault used to prove fail-closed slot
    /// authority. This remains a HOST mock seam only.
    pub const fn with_invalid_slot_fault(committed: CommittedInstallerState) -> Self {
        Self {
            committed,
            trial: None,
            force_invalid_slot_decision: true,
            boot_attempts: 0,
            last_display: None,
        }
    }

    pub const fn committed(&self) -> CommittedInstallerState {
        self.committed
    }

    pub const fn boot_attempts(&self) -> u32 {
        self.boot_attempts
    }

    pub const fn last_display(&self) -> Option<BootVersionDisplay> {
        self.last_display
    }

    pub const fn has_trial(&self) -> bool {
        self.trial.is_some()
    }

    /// Authoritatively recheck floor/keyset and stage only the inactive slot.
    pub fn prepare_trial(
        &mut self,
        package: VerifiedPackage,
        presence: UpdatePresence,
    ) -> Result<SlotId, UpdateError> {
        presence.enforce()?;
        if self.trial.is_some() {
            return Err(UpdateError::InvalidTransition);
        }
        if package.manifest().version() <= self.committed.floor {
            return Err(UpdateError::InstallerNotStrictlyNewer);
        }
        if package.manifest().signing_keyset_id() != self.committed.keyset_id {
            return Err(UpdateError::InstallerKeysetMismatch);
        }
        let slot = self.committed.active_slot.inactive();
        if self.force_invalid_slot_decision || slot == self.committed.active_slot {
            return Err(UpdateError::InvalidSlotDecision);
        }
        // Touch the private staged image at the mock write boundary without
        // copying it or exposing it to the public API.
        let _candidate_image = package.image_bytes()?;
        self.trial = Some(TrialState {
            package,
            slot,
            boot_attempted: false,
            report_verified: false,
        });
        Ok(slot)
    }

    /// Attempt the candidate's first boot and emit its version-display fact.
    /// A mismatch or unconfirmed report leaves committed state unchanged and
    /// retains the old-slot fallback option.
    pub fn attempt_first_boot(
        &mut self,
        report: FirstBootReport,
        presence: UpdatePresence,
    ) -> Result<BootVersionDisplay, UpdateError> {
        presence.enforce()?;
        let trial = self.trial.as_mut().ok_or(UpdateError::InvalidTransition)?;
        if trial.boot_attempted {
            return Err(UpdateError::InvalidTransition);
        }
        trial.boot_attempted = true;
        let display = BootVersionDisplay::new(trial.package.manifest().version());
        self.boot_attempts = self.boot_attempts.saturating_add(1);
        self.last_display = Some(display);
        if report.slot != trial.slot
            || report.version != trial.package.manifest().version()
            || report.firmware_image_sha256 != trial.package.firmware_image_sha256()
            || report.target_keyset_id != trial.package.manifest().target_keyset_id()
        {
            return Err(UpdateError::BootReportMismatch);
        }
        if !report.confirmed_success {
            return Err(UpdateError::BootNotConfirmed);
        }
        trial.report_verified = true;
        Ok(display)
    }

    /// Atomically commit slot, floor, target key set and image hash only after
    /// one exact successful first-boot report.
    pub fn commit_confirmed_boot(
        &mut self,
        presence: UpdatePresence,
    ) -> Result<CommittedInstallerState, UpdateError> {
        presence.enforce()?;
        let trial = self.trial.as_ref().ok_or(UpdateError::InvalidTransition)?;
        if !trial.report_verified {
            return Err(UpdateError::BootNotConfirmed);
        }
        let next = CommittedInstallerState::new(
            trial.slot,
            trial.package.manifest().version(),
            trial.package.manifest().target_keyset_id(),
            trial.package.firmware_image_sha256(),
        );
        let consumed = self.trial.take().ok_or(UpdateError::InvalidTransition)?;
        self.committed = next;
        drop(consumed);
        Ok(next)
    }

    /// Discard any uncommitted candidate and boot the unchanged old slot.
    pub fn fallback_to_committed(
        &mut self,
        presence: UpdatePresence,
    ) -> Result<BootVersionDisplay, UpdateError> {
        presence.enforce()?;
        let trial = self.trial.take().ok_or(UpdateError::InvalidTransition)?;
        drop(trial);
        let display = BootVersionDisplay::new(self.committed.floor);
        self.boot_attempts = self.boot_attempts.saturating_add(1);
        self.last_display = Some(display);
        Ok(display)
    }
}
