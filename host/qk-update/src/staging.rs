//! One-read mock media selection and private staging ownership.

use crate::{
    wipe::WipingByteVec, UpdateError, MAX_PACKAGE_BYTES, MIN_PACKAGE_BYTES, UPDATE_FILE_NAME,
};

/// Wallet/card absence facts required at every update boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdatePresence {
    wallet_session_active: bool,
    card_present: bool,
}

impl UpdatePresence {
    /// Construct explicit presence facts.
    pub const fn new(wallet_session_active: bool, card_present: bool) -> Self {
        Self {
            wallet_session_active,
            card_present,
        }
    }

    /// The required clear update posture.
    pub const fn clear() -> Self {
        Self::new(false, false)
    }

    pub(crate) const fn enforce(self) -> Result<(), UpdateError> {
        if self.wallet_session_active {
            return Err(UpdateError::WalletSessionActive);
        }
        if self.card_present {
            return Err(UpdateError::CardPresent);
        }
        Ok(())
    }
}

/// One root-level mock candidate. It represents no real filesystem or media.
pub struct MockMediaCandidate {
    name: String,
    bytes: Vec<u8>,
}

impl MockMediaCandidate {
    /// Own one exact mock root filename and its bytes.
    pub fn new(name: &str, bytes: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            bytes,
        }
    }

    /// Construct the sole canonical update candidate.
    pub fn canonical(bytes: Vec<u8>) -> Self {
        Self::new(UPDATE_FILE_NAME, bytes)
    }
}

/// Closed mock faults for the read/copy boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MockMediaFaults {
    read_failure: bool,
    copy_failure_after: Option<usize>,
}

impl MockMediaFaults {
    /// Fail the sole media read before candidate bytes are copied.
    pub const fn read_failure() -> Self {
        Self {
            read_failure: true,
            copy_failure_after: None,
        }
    }

    /// Fail the private copy after exactly `byte_count` bytes were staged.
    pub const fn copy_failure_after(byte_count: usize) -> Self {
        Self {
            read_failure: false,
            copy_failure_after: Some(byte_count),
        }
    }
}

/// One-use read-only-media mock. It deliberately exposes no reread method.
pub struct MockReadOnlyMedia {
    candidates: Vec<MockMediaCandidate>,
    faults: MockMediaFaults,
    consumed: bool,
    read_attempts: u8,
}

impl MockReadOnlyMedia {
    /// Construct a fault-free mock root.
    pub fn new(candidates: Vec<MockMediaCandidate>) -> Self {
        Self::with_faults(candidates, MockMediaFaults::default())
    }

    /// Construct a mock root with one closed fault configuration.
    pub fn with_faults(candidates: Vec<MockMediaCandidate>, faults: MockMediaFaults) -> Self {
        Self {
            candidates,
            faults,
            consumed: false,
            read_attempts: 0,
        }
    }

    /// Number of attempted mock media reads.
    pub const fn read_attempts(&self) -> u8 {
        self.read_attempts
    }

    /// Whether the one-read capability has been consumed.
    pub const fn consumed(&self) -> bool {
        self.consumed
    }
}

/// Private staged package owner. It is intentionally neither clonable nor
/// printable and exposes no public byte accessor.
pub struct StagedPackage {
    bytes: WipingByteVec,
}

impl StagedPackage {
    /// Exact staged byte count, without exposing content.
    pub fn byte_length(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Copy the sole canonical candidate exactly once into private staging.
pub fn stage_from_media(
    media: &mut MockReadOnlyMedia,
    presence: UpdatePresence,
) -> Result<StagedPackage, UpdateError> {
    presence.enforce()?;
    if media.consumed {
        return Err(UpdateError::MediaAlreadyRead);
    }
    media.consumed = true;
    media.read_attempts = media.read_attempts.saturating_add(1);
    if media.faults.read_failure {
        return Err(UpdateError::MediaReadFailed);
    }
    let [candidate] = media.candidates.as_slice() else {
        return Err(if media.candidates.is_empty() {
            UpdateError::UpdateCandidateMissing
        } else {
            UpdateError::SecondUpdateCandidate
        });
    };
    if candidate.name.as_bytes() != UPDATE_FILE_NAME.as_bytes() {
        return Err(UpdateError::UpdateCandidateMissing);
    }
    if !(MIN_PACKAGE_BYTES..=MAX_PACKAGE_BYTES).contains(&candidate.bytes.len()) {
        return Err(UpdateError::PackageLengthOutOfBounds);
    }

    let mut staged = WipingByteVec::new();
    staged
        .try_reserve_exact(candidate.bytes.len())
        .map_err(|_| UpdateError::StagingAllocationFailed)?;
    for (position, byte) in candidate.bytes.iter().copied().enumerate() {
        if media.faults.copy_failure_after == Some(position) {
            return Err(UpdateError::StagingCopyFailed);
        }
        staged.push(byte);
    }
    if media.faults.copy_failure_after == Some(candidate.bytes.len()) {
        return Err(UpdateError::StagingCopyFailed);
    }
    Ok(StagedPackage { bytes: staged })
}
