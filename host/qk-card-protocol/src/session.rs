//! Volatile session identity, ordering, one-use, and cap accounting.

use crate::{
    wipe, A2Purpose, CommandRef, DescriptorSelector, Instruction, Mode, ProtocolError, ResponseRef,
    MAX_AGGREGATE_BYTES, MAX_EXCHANGES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_SIGNATURES,
};

const OPEN_REQUEST_BYTES: usize = 24;
const OPEN_RESPONSE_BYTES: usize = 23;

#[derive(Clone, Copy)]
enum PendingEcho {
    GetInfo,
    ReadDChunk {
        selector: DescriptorSelector,
        offset: u16,
    },
    ExportA2 {
        purpose: A2Purpose,
    },
    SignDigest {
        input_index: u32,
    },
    BeginProvision,
    WriteChunk {
        next_offset: u16,
    },
    Commit,
    Abort,
}

/// Persistent lifecycle code returned by GET_INFO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Lifecycle {
    Unprovisioned = 0x00,
    Staging = 0x01,
    Committed = 0x02,
    RetiredError = 0xff,
}

impl Lifecycle {
    pub const fn byte(self) -> u8 {
        self as u8
    }
}

const OP_INFO: u16 = 1 << 0;
const OP_READ_D: u16 = 1 << 1;
const OP_EXPORT_A2: u16 = 1 << 2;
const OP_SIGN: u16 = 1 << 3;
const OP_BEGIN: u16 = 1 << 4;
const OP_WRITE: u16 = 1 << 5;
const OP_COMMIT: u16 = 1 << 6;
const OP_ABORT: u16 = 1 << 7;

/// Compute the immutable contextual operation mask.
pub const fn allowed_operations(
    lifecycle: Lifecycle,
    mode: Mode,
    staging_complete: bool,
) -> Result<u16, ProtocolError> {
    match lifecycle {
        Lifecycle::Unprovisioned => match mode {
            Mode::Setup | Mode::KitRestore => Ok(OP_INFO | OP_BEGIN),
            Mode::Normal | Mode::Rescue => Err(ProtocolError::LifecycleRejected),
        },
        Lifecycle::Staging => match mode {
            Mode::Setup | Mode::KitRestore if staging_complete => {
                Ok(OP_INFO | OP_BEGIN | OP_COMMIT | OP_ABORT)
            }
            Mode::Setup | Mode::KitRestore => Ok(OP_INFO | OP_BEGIN | OP_WRITE | OP_ABORT),
            Mode::Normal | Mode::Rescue => Err(ProtocolError::LifecycleRejected),
        },
        Lifecycle::Committed => match mode {
            Mode::Setup => Ok(OP_INFO | OP_READ_D | OP_EXPORT_A2),
            Mode::Normal | Mode::Rescue => Ok(OP_INFO | OP_READ_D | OP_EXPORT_A2 | OP_SIGN),
            Mode::KitRestore => Ok(OP_INFO | OP_READ_D),
        },
        Lifecycle::RetiredError => Ok(OP_INFO),
    }
}

/// Stateful verifier for one already-open volatile session.
///
/// Semantic lifecycle checks remain the card model's responsibility. This
/// owner enforces the byte-protocol invariants shared by every lifecycle.
pub struct SessionTracker {
    session_id: [u8; 16],
    mode: Mode,
    next_sequence: u32,
    exchange_count: u16,
    aggregate_bytes: usize,
    outstanding: bool,
    pending_sequence: u32,
    pending_instruction: Option<Instruction>,
    pending_echo: Option<PendingEcho>,
    pending_response_min: usize,
    pending_response_max: usize,
    read_step: u8,
    a2_exported: bool,
    signature_count: u8,
    signing_bound: bool,
    signing_wallet_id: [u8; 32],
    signing_review_hash: [u8; 32],
    last_input_index: u32,
    terminated: bool,
}

impl SessionTracker {
    /// Start after an accepted OPEN request and response.
    pub fn new(
        mode: Mode,
        session_id: &[u8; 16],
        open_request_bytes: usize,
        open_response_bytes: usize,
    ) -> Result<Self, ProtocolError> {
        if open_request_bytes != OPEN_REQUEST_BYTES || open_response_bytes != OPEN_RESPONSE_BYTES {
            return Err(ProtocolError::SessionStateRejected);
        }
        let aggregate_bytes = open_request_bytes
            .checked_add(open_response_bytes)
            .ok_or(ProtocolError::SessionStateRejected)?;
        if aggregate_bytes > MAX_AGGREGATE_BYTES {
            return Err(ProtocolError::SessionStateRejected);
        }
        Ok(Self {
            session_id: *session_id,
            mode,
            next_sequence: 1,
            exchange_count: 1,
            aggregate_bytes,
            outstanding: false,
            pending_sequence: 0,
            pending_instruction: None,
            pending_echo: None,
            pending_response_min: 0,
            pending_response_max: 0,
            read_step: 0,
            a2_exported: false,
            signature_count: 0,
            signing_bound: false,
            signing_wallet_id: [0; 32],
            signing_review_hash: [0; 32],
            last_input_index: 0,
            terminated: false,
        })
    }

    pub const fn mode(&self) -> Mode {
        self.mode
    }

    pub const fn next_sequence(&self) -> u32 {
        self.next_sequence
    }

    pub const fn exchange_count(&self) -> u16 {
        self.exchange_count
    }

    pub const fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Admit one parsed post-OPEN request and reserve its serialized bytes.
    pub fn begin_exchange(
        &mut self,
        command: CommandRef<'_>,
        request_bytes: usize,
    ) -> Result<(), ProtocolError> {
        if self.terminated || self.outstanding || command.envelope().is_none() {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        if request_bytes > MAX_REQUEST_BYTES || request_bytes != request_length(command) {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        if self.exchange_count >= MAX_EXCHANGES {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        let envelope = match command.envelope() {
            Some(value) => value,
            None => return self.fail(ProtocolError::SessionStateRejected),
        };
        if envelope.session_id() != &self.session_id {
            return self.fail(ProtocolError::SessionIdMismatch);
        }
        if envelope.sequence() != self.next_sequence {
            return self.fail(ProtocolError::SequenceRejected);
        }
        let aggregate = match self.aggregate_bytes.checked_add(request_bytes) {
            Some(value) => value,
            None => return self.fail(ProtocolError::SessionStateRejected),
        };
        if aggregate > MAX_AGGREGATE_BYTES {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        let instruction = command.instruction();
        let pending_echo = match PendingEcho::from_command(command) {
            Ok(value) => value,
            Err(error) => return self.fail(error),
        };
        let (response_min, response_max) = match success_response_bounds(command) {
            Ok(value) => value,
            Err(error) => return self.fail(error),
        };
        self.validate_one_use_and_order(command)?;
        self.aggregate_bytes = aggregate;
        self.pending_sequence = envelope.sequence();
        self.pending_instruction = Some(instruction);
        self.pending_echo = Some(pending_echo);
        self.pending_response_min = response_min;
        self.pending_response_max = response_max;
        self.outstanding = true;
        Ok(())
    }

    /// Validate and account the parsed success response for the outstanding request.
    pub fn finish_success(
        &mut self,
        response: ResponseRef<'_>,
        response_bytes: usize,
    ) -> Result<(), ProtocolError> {
        if self.terminated || !self.outstanding {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        if response_bytes > MAX_RESPONSE_BYTES
            || !(self.pending_response_min..=self.pending_response_max).contains(&response_bytes)
            || response_length(response) != Some(response_bytes)
        {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        let aggregate = match self.aggregate_bytes.checked_add(response_bytes) {
            Some(value) => value,
            None => return self.fail(ProtocolError::SessionStateRejected),
        };
        if aggregate > MAX_AGGREGATE_BYTES {
            return self.fail(ProtocolError::SessionStateRejected);
        }
        if let Err(error) = self.validate_success_response(response) {
            return self.fail(error);
        }
        self.aggregate_bytes = aggregate;
        self.exchange_count += 1;
        self.next_sequence = match self.pending_sequence.checked_add(1) {
            Some(value) => value,
            None => return self.fail(ProtocolError::SequenceRejected),
        };
        let command_terminates = matches!(
            self.pending_instruction,
            Some(Instruction::Commit | Instruction::Abort)
        );
        self.pending_sequence = 0;
        self.pending_instruction = None;
        self.pending_echo = None;
        self.pending_response_min = 0;
        self.pending_response_max = 0;
        self.outstanding = false;
        if command_terminates {
            self.terminate();
        }
        Ok(())
    }

    /// Account an exact bodyless named rejection and end the session.
    pub fn finish_rejection(&mut self, response_bytes: usize) -> Result<(), ProtocolError> {
        let aggregate = self.aggregate_bytes.checked_add(response_bytes);
        let valid = !self.terminated
            && self.outstanding
            && response_bytes == 2
            && aggregate.is_some_and(|value| value <= MAX_AGGREGATE_BYTES);
        if let Some(value) = aggregate.filter(|_| valid) {
            self.aggregate_bytes = value;
        }
        if valid {
            self.exchange_count = self.exchange_count.saturating_add(1);
        }
        self.terminate();
        if valid {
            Ok(())
        } else {
            Err(ProtocolError::SessionStateRejected)
        }
    }

    pub fn terminate(&mut self) {
        if !self.terminated {
            wipe::bytes(&mut self.session_id);
            wipe::bytes(&mut self.signing_wallet_id);
            wipe::bytes(&mut self.signing_review_hash);
            self.terminated = true;
            self.outstanding = false;
            self.pending_sequence = 0;
            self.pending_instruction = None;
            self.pending_echo = None;
            self.pending_response_min = 0;
            self.pending_response_max = 0;
        }
    }

    fn validate_one_use_and_order(&mut self, command: CommandRef<'_>) -> Result<(), ProtocolError> {
        match command {
            CommandRef::ReadDChunk {
                selector, offset, ..
            } => {
                let expected = [
                    (DescriptorSelector::Receive, 0),
                    (DescriptorSelector::Receive, 192),
                    (DescriptorSelector::Change, 0),
                    (DescriptorSelector::Change, 192),
                ];
                let Some((expected_selector, expected_offset)) =
                    expected.get(usize::from(self.read_step)).copied()
                else {
                    return self.fail(ProtocolError::ModeOrOperationRejected);
                };
                if selector != expected_selector || offset != expected_offset {
                    return self.fail(ProtocolError::ModeOrOperationRejected);
                }
                self.read_step += 1;
            }
            CommandRef::ExportA2 { purpose, .. } => {
                let expected = match self.mode {
                    Mode::Setup => Some(A2Purpose::Setup),
                    Mode::Normal => Some(A2Purpose::Normal),
                    Mode::Rescue => Some(A2Purpose::Rescue),
                    Mode::KitRestore => None,
                };
                if self.a2_exported || expected != Some(purpose) {
                    return self.fail(ProtocolError::ModeOrOperationRejected);
                }
                self.a2_exported = true;
            }
            CommandRef::SignDigest {
                wallet_id,
                review_hash,
                input_index,
                ..
            } => {
                if self.signature_count >= MAX_SIGNATURES {
                    return self.fail(ProtocolError::ModeOrOperationRejected);
                }
                if self.signing_bound {
                    if wallet_id != &self.signing_wallet_id
                        || review_hash != &self.signing_review_hash
                    {
                        return self.fail(ProtocolError::SigningBindingRejected);
                    }
                    if input_index <= self.last_input_index {
                        return self.fail(ProtocolError::SigningBindingRejected);
                    }
                } else {
                    self.signing_wallet_id.copy_from_slice(wallet_id);
                    self.signing_review_hash.copy_from_slice(review_hash);
                    self.signing_bound = true;
                }
                self.last_input_index = input_index;
                self.signature_count += 1;
            }
            CommandRef::Select | CommandRef::OpenSession { .. } => {
                return self.fail(ProtocolError::SessionStateRejected);
            }
            CommandRef::GetInfo { .. }
            | CommandRef::BeginProvision { .. }
            | CommandRef::WriteChunk { .. }
            | CommandRef::Commit { .. }
            | CommandRef::Abort { .. } => {}
        }
        Ok(())
    }

    fn validate_success_response(&self, response: ResponseRef<'_>) -> Result<(), ProtocolError> {
        let pending = self
            .pending_echo
            .ok_or(ProtocolError::SessionStateRejected)?;
        let envelope = response_envelope(pending, response)?;
        if envelope.session_id() != &self.session_id {
            return Err(ProtocolError::SessionIdMismatch);
        }
        if envelope.sequence() != self.pending_sequence {
            return Err(ProtocolError::SequenceRejected);
        }
        validate_echo(pending, response, &self.signing_review_hash)
    }

    fn fail<T>(&mut self, error: ProtocolError) -> Result<T, ProtocolError> {
        self.terminate();
        Err(error)
    }
}

impl PendingEcho {
    fn from_command(command: CommandRef<'_>) -> Result<Self, ProtocolError> {
        match command {
            CommandRef::GetInfo { .. } => Ok(Self::GetInfo),
            CommandRef::ReadDChunk {
                selector, offset, ..
            } => Ok(Self::ReadDChunk { selector, offset }),
            CommandRef::ExportA2 { purpose, .. } => Ok(Self::ExportA2 { purpose }),
            CommandRef::SignDigest { input_index, .. } => Ok(Self::SignDigest { input_index }),
            CommandRef::BeginProvision { .. } => Ok(Self::BeginProvision),
            CommandRef::WriteChunk { offset, bytes, .. } => {
                if !matches!(
                    (offset, bytes.len()),
                    (0 | 192 | 384 | 576, crate::MAX_WRITE_CHUNK_BYTES) | (768, 13)
                ) {
                    return Err(ProtocolError::ProvisioningOrderRejected);
                }
                let byte_count = u16::try_from(bytes.len())
                    .map_err(|_| ProtocolError::ProvisioningOrderRejected)?;
                let next_offset = offset
                    .checked_add(byte_count)
                    .ok_or(ProtocolError::ProvisioningOrderRejected)?;
                Ok(Self::WriteChunk { next_offset })
            }
            CommandRef::Commit { .. } => Ok(Self::Commit),
            CommandRef::Abort { .. } => Ok(Self::Abort),
            CommandRef::Select | CommandRef::OpenSession { .. } => {
                Err(ProtocolError::SessionStateRejected)
            }
        }
    }
}

fn response_envelope<'a>(
    pending: PendingEcho,
    response: ResponseRef<'a>,
) -> Result<crate::EnvelopeRef<'a>, ProtocolError> {
    match (pending, response) {
        (PendingEcho::GetInfo, ResponseRef::GetInfo { envelope, .. })
        | (PendingEcho::ReadDChunk { .. }, ResponseRef::ReadDChunk { envelope, .. })
        | (PendingEcho::ExportA2 { .. }, ResponseRef::ExportA2 { envelope, .. })
        | (PendingEcho::SignDigest { .. }, ResponseRef::SignDigest { envelope, .. })
        | (PendingEcho::BeginProvision, ResponseRef::BeginProvision { envelope })
        | (PendingEcho::WriteChunk { .. }, ResponseRef::WriteChunk { envelope, .. })
        | (PendingEcho::Commit, ResponseRef::Commit { envelope })
        | (PendingEcho::Abort, ResponseRef::Abort { envelope }) => Ok(envelope),
        _ => Err(ProtocolError::SessionStateRejected),
    }
}

fn validate_echo(
    pending: PendingEcho,
    response: ResponseRef<'_>,
    signing_review_hash: &[u8; 32],
) -> Result<(), ProtocolError> {
    match (pending, response) {
        (PendingEcho::GetInfo, ResponseRef::GetInfo { .. })
        | (PendingEcho::BeginProvision, ResponseRef::BeginProvision { .. })
        | (PendingEcho::Commit, ResponseRef::Commit { .. })
        | (PendingEcho::Abort, ResponseRef::Abort { .. }) => Ok(()),
        (
            PendingEcho::ReadDChunk {
                selector: expected_selector,
                offset: expected_offset,
            },
            ResponseRef::ReadDChunk {
                selector, offset, ..
            },
        ) if selector == expected_selector && offset == expected_offset => Ok(()),
        (PendingEcho::ReadDChunk { .. }, ResponseRef::ReadDChunk { .. }) => {
            Err(ProtocolError::ModeOrOperationRejected)
        }
        (
            PendingEcho::ExportA2 {
                purpose: expected_purpose,
            },
            ResponseRef::ExportA2 { purpose, .. },
        ) if purpose == expected_purpose => Ok(()),
        (PendingEcho::ExportA2 { .. }, ResponseRef::ExportA2 { .. }) => {
            Err(ProtocolError::ModeOrOperationRejected)
        }
        (
            PendingEcho::WriteChunk {
                next_offset: expected_offset,
            },
            ResponseRef::WriteChunk { next_offset, .. },
        ) if next_offset == expected_offset => Ok(()),
        (PendingEcho::WriteChunk { .. }, ResponseRef::WriteChunk { .. }) => {
            Err(ProtocolError::ProvisioningOrderRejected)
        }
        (
            PendingEcho::SignDigest {
                input_index: expected_index,
            },
            ResponseRef::SignDigest {
                review_hash,
                input_index,
                ..
            },
        ) if review_hash == signing_review_hash && input_index == expected_index => Ok(()),
        (PendingEcho::SignDigest { .. }, ResponseRef::SignDigest { .. }) => {
            Err(ProtocolError::SigningBindingRejected)
        }
        _ => Err(ProtocolError::SessionStateRejected),
    }
}

fn response_length(response: ResponseRef<'_>) -> Option<usize> {
    match response {
        ResponseRef::Rejected(_) | ResponseRef::Select => Some(2),
        ResponseRef::OpenSession { .. }
        | ResponseRef::BeginProvision { .. }
        | ResponseRef::Commit { .. }
        | ResponseRef::Abort { .. } => Some(23),
        ResponseRef::GetInfo { .. } => Some(160),
        ResponseRef::ReadDChunk { bytes, .. } => 26usize.checked_add(bytes.len()),
        ResponseRef::ExportA2 { .. } => Some(56),
        ResponseRef::SignDigest { signature_der, .. } => 93usize.checked_add(signature_der.len()),
        ResponseRef::WriteChunk { .. } => Some(25),
    }
}

fn request_length(command: CommandRef<'_>) -> usize {
    match command {
        CommandRef::GetInfo { .. } | CommandRef::Commit { .. } | CommandRef::Abort { .. } => 27,
        CommandRef::ReadDChunk { .. } => 30,
        CommandRef::ExportA2 { .. } => 28,
        CommandRef::SignDigest { .. } => 132,
        CommandRef::BeginProvision { .. } => 40,
        CommandRef::WriteChunk { bytes, .. } => 29 + bytes.len(),
        CommandRef::Select => 12,
        CommandRef::OpenSession { .. } => OPEN_REQUEST_BYTES,
    }
}

fn success_response_bounds(command: CommandRef<'_>) -> Result<(usize, usize), ProtocolError> {
    match command {
        CommandRef::GetInfo { .. } => Ok((160, 160)),
        CommandRef::ReadDChunk { offset: 0, .. } => Ok((218, 218)),
        CommandRef::ReadDChunk { offset: 192, .. } => Ok((140, 140)),
        CommandRef::ReadDChunk { .. } => Err(ProtocolError::ModeOrOperationRejected),
        CommandRef::ExportA2 { .. } => Ok((56, 56)),
        CommandRef::SignDigest { .. } => Ok((101, 165)),
        CommandRef::BeginProvision { .. }
        | CommandRef::Commit { .. }
        | CommandRef::Abort { .. } => Ok((23, 23)),
        CommandRef::WriteChunk { .. } => Ok((25, 25)),
        CommandRef::Select | CommandRef::OpenSession { .. } => {
            Err(ProtocolError::SessionStateRejected)
        }
    }
}

impl Drop for SessionTracker {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnvelopeRef;

    #[test]
    fn masks_are_exact() {
        assert_eq!(
            allowed_operations(Lifecycle::Unprovisioned, Mode::Setup, false),
            Ok(0x11)
        );
        assert_eq!(
            allowed_operations(Lifecycle::Staging, Mode::Setup, false),
            Ok(0xb1)
        );
        assert_eq!(
            allowed_operations(Lifecycle::Staging, Mode::Setup, true),
            Ok(0xd1)
        );
        assert_eq!(
            allowed_operations(Lifecycle::Committed, Mode::Setup, false),
            Ok(0x07)
        );
        assert_eq!(
            allowed_operations(Lifecycle::Committed, Mode::Normal, false),
            Ok(0x0f)
        );
        assert_eq!(
            allowed_operations(Lifecycle::Committed, Mode::KitRestore, false),
            Ok(0x03)
        );
        assert_eq!(
            allowed_operations(Lifecycle::RetiredError, Mode::Rescue, false),
            Ok(0x01)
        );
    }

    #[test]
    fn sequence_and_identity_are_exact() {
        let id = [7u8; 16];
        let wrong = [8u8; 16];
        let mut tracker = SessionTracker::new(Mode::Normal, &id, 24, 23).expect("open");
        let error = tracker
            .begin_exchange(
                CommandRef::GetInfo {
                    envelope: EnvelopeRef::new(&wrong, 1),
                },
                27,
            )
            .expect_err("wrong session");
        assert_eq!(error, ProtocolError::SessionIdMismatch);
        assert!(tracker.is_terminated());
    }

    #[test]
    fn rejection_response_cannot_cross_aggregate_cap() {
        let id = [7u8; 16];
        let mut tracker = SessionTracker::new(Mode::Setup, &id, 24, 23).expect("open");
        tracker
            .begin_exchange(
                CommandRef::GetInfo {
                    envelope: EnvelopeRef::new(&id, 1),
                },
                27,
            )
            .expect("request");
        tracker.aggregate_bytes = MAX_AGGREGATE_BYTES;
        assert_eq!(
            tracker.finish_rejection(2),
            Err(ProtocolError::SessionStateRejected)
        );
        assert_eq!(tracker.aggregate_bytes(), MAX_AGGREGATE_BYTES);
        assert!(tracker.is_terminated());
    }
}
