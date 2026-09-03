//! Persistent lifecycle and command semantics for the HOST card model.

use crate::{crypto, wipe, EXTENDED_KEY_BYTES, MAX_DER_BYTES, RECORD_BYTES};
use core::fmt;
use qk_card_protocol::{
    CommandRef, EnvelopeRef, Lifecycle as ModelLifecycle, Media, Mode as ModelMode, ProtocolError,
};

const MAX_COMMANDS: u16 = qk_card_protocol::MAX_EXCHANGES;
const MAX_SIGNATURES: u8 = qk_card_protocol::MAX_SIGNATURES;
const OPEN_REQUEST_BYTES: usize = 24;
const OPEN_RESPONSE_BYTES: usize = 23;
const ENVELOPED_RESPONSE_BYTES: usize = 23;

/// Test-only failure seams. Each injected fault is consumed by the next
/// applicable operation; none exists in the wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    PersistentWrite,
    Transaction,
    CorruptCommittedDigest,
    ChildDerivation,
    CryptographicOperation,
    CaughtUnwind,
    InteriorCryptoUnwind,
}

/// Fixed, attacker-byte-free semantic rejection categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelError {
    ContactInterfaceRequired,
    ProtocolVersionMismatch,
    SessionStateRejected,
    SessionIdMismatch,
    SequenceRejected,
    ModeOrOperationRejected,
    LifecycleRejected,
    ProvisioningOrderRejected,
    RecordRejected,
    WalletBindingRejected,
    DerivationPathRejected,
    ChildDerivationRejected,
    SigningBindingRejected,
    CryptographicOperationRejected,
    InternalIntegrityFailure,
}

impl ModelError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ContactInterfaceRequired => "ContactInterfaceRequired",
            Self::ProtocolVersionMismatch => "ProtocolVersionMismatch",
            Self::SessionStateRejected => "SessionStateRejected",
            Self::SessionIdMismatch => "SessionIdMismatch",
            Self::SequenceRejected => "SequenceRejected",
            Self::ModeOrOperationRejected => "ModeOrOperationRejected",
            Self::LifecycleRejected => "LifecycleRejected",
            Self::ProvisioningOrderRejected => "ProvisioningOrderRejected",
            Self::RecordRejected => "RecordRejected",
            Self::WalletBindingRejected => "WalletBindingRejected",
            Self::DerivationPathRejected => "DerivationPathRejected",
            Self::ChildDerivationRejected => "ChildDerivationRejected",
            Self::SigningBindingRejected => "SigningBindingRejected",
            Self::CryptographicOperationRejected => "CryptographicOperationRejected",
            Self::InternalIntegrityFailure => "InternalIntegrityFailure",
        }
    }

    pub const fn status_word(self) -> u16 {
        match self {
            Self::ProtocolVersionMismatch => 0x6f01,
            Self::ContactInterfaceRequired => 0x6f02,
            Self::SessionStateRejected => 0x6f03,
            Self::SessionIdMismatch => 0x6f04,
            Self::SequenceRejected => 0x6f05,
            Self::ModeOrOperationRejected => 0x6f06,
            Self::LifecycleRejected => 0x6f07,
            Self::ProvisioningOrderRejected => 0x6f08,
            Self::RecordRejected => 0x6f09,
            Self::WalletBindingRejected => 0x6f0a,
            Self::DerivationPathRejected => 0x6f0b,
            Self::ChildDerivationRejected => 0x6f0c,
            Self::SigningBindingRejected => 0x6f0d,
            Self::CryptographicOperationRejected => 0x6f0e,
            Self::InternalIntegrityFailure => 0x6f0f,
        }
    }
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for ModelError {}

/// Public record facts returned by the modeled GET_INFO operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardInfo {
    pub protocol_version: u8,
    pub record_version: u8,
    pub lifecycle: ModelLifecycle,
    pub profile: u8,
    pub role: u8,
    pub instance_id: [u8; 16],
    pub wallet_id: [u8; 32],
    pub origin_fingerprint: [u8; 4],
    pub account_xpub: [u8; EXTENDED_KEY_BYTES],
    pub allowed_operations: u16,
}

/// Move-only signature reply; DER scratch is wiped on drop.
pub struct SignReply {
    review_hash: [u8; 32],
    input_index: u32,
    public_key: [u8; 33],
    der: [u8; MAX_DER_BYTES],
    der_len: usize,
}

impl SignReply {
    pub fn review_hash(&self) -> &[u8; 32] {
        &self.review_hash
    }
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }
    pub fn public_key(&self) -> &[u8; 33] {
        &self.public_key
    }
    pub fn der(&self) -> &[u8] {
        &self.der[..self.der_len]
    }
}

impl Drop for SignReply {
    fn drop(&mut self) {
        wipe::bytes(&mut self.review_hash);
        wipe::bytes(&mut self.public_key);
        wipe::bytes(&mut self.der);
        self.input_index = 0;
        self.der_len = 0;
    }
}

struct Staging {
    mode: ModelMode,
    ordinal: u8,
    nonce: [u8; 12],
    record: wipe::Secret<RECORD_BYTES>,
    filled: usize,
}

impl Drop for Staging {
    fn drop(&mut self) {
        wipe::bytes(&mut self.nonce);
        self.ordinal = 0;
        self.filled = 0;
    }
}

struct Committed {
    record: wipe::Secret<RECORD_BYTES>,
    account_xpub: [u8; EXTENDED_KEY_BYTES],
    digest: wipe::Secret<32>,
}

impl Drop for Committed {
    fn drop(&mut self) {
        wipe::bytes(&mut self.account_xpub);
    }
}

enum Storage {
    Unprovisioned,
    Staging(Staging),
    Committed(Committed),
    RetiredError,
}

struct Session {
    mode: ModelMode,
    id: [u8; 16],
    next_sequence: u32,
    command_count: u16,
    aggregate_bytes: usize,
    read_step: u8,
    a2_exported: bool,
    sign_count: u8,
    last_input: Option<u32>,
    signing_wallet: Option<wipe::Secret<32>>,
    signing_review: Option<wipe::Secret<32>>,
}

impl Session {
    fn new(mode: ModelMode, id: [u8; 16]) -> Self {
        Self {
            mode,
            id,
            next_sequence: 1,
            command_count: 1,
            aggregate_bytes: OPEN_REQUEST_BYTES + OPEN_RESPONSE_BYTES,
            read_step: 0,
            a2_exported: false,
            sign_count: 0,
            last_input: None,
            signing_wallet: None,
            signing_review: None,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        wipe::bytes(&mut self.id);
        self.next_sequence = 0;
        self.command_count = 0;
        self.aggregate_bytes = 0;
    }
}

/// Stateful test-only card model. It is deliberately neither Clone nor Debug.
pub struct CardModel {
    selected: bool,
    storage: Storage,
    session: Option<Session>,
    pending_fault: Option<FaultPoint>,
    next_signature_high_s: bool,
    response_budget: Option<usize>,
}

impl Default for CardModel {
    fn default() -> Self {
        Self::new()
    }
}

impl CardModel {
    pub const fn new() -> Self {
        Self {
            selected: false,
            storage: Storage::Unprovisioned,
            session: None,
            pending_fault: None,
            next_signature_high_s: false,
            response_budget: None,
        }
    }

    pub fn lifecycle(&self) -> ModelLifecycle {
        match self.storage {
            Storage::Unprovisioned => ModelLifecycle::Unprovisioned,
            Storage::Staging(_) => ModelLifecycle::Staging,
            Storage::Committed(_) => ModelLifecycle::Committed,
            Storage::RetiredError => ModelLifecycle::RetiredError,
        }
    }

    /// Reset/deselect clears all volatile state and preserves persistent state.
    pub fn deselect(&mut self) {
        self.selected = false;
        self.session = None;
    }

    pub fn select(&mut self, contact_t1: bool) -> Result<(), ModelError> {
        self.deselect();
        if !contact_t1 {
            return Err(ModelError::ContactInterfaceRequired);
        }
        self.selected = true;
        Ok(())
    }

    /// Parse one exact hostile APDU through qk-card-protocol and execute it.
    /// Rejections are returned by name and encoded bodylessly into the first
    /// two output bytes; successful responses return their exact byte length.
    pub fn process_apdu(
        &mut self,
        media: Media,
        command_bytes: &[u8],
        output: &mut [u8; qk_card_protocol::MAX_RESPONSE_BYTES],
    ) -> Result<usize, ProtocolError> {
        output.fill(0);
        let command = match qk_card_protocol::parse_command(media, command_bytes) {
            Ok(command) => command,
            Err(error) => {
                self.deselect();
                let _ = qk_card_protocol::encode_rejection(error, output);
                return Err(error);
            }
        };
        let (accounted_request, accounting_overflow) = match command {
            CommandRef::Select => (None, false),
            CommandRef::OpenSession { .. } => (Some(command_bytes.len()), false),
            _ => match self.session.as_ref() {
                Some(session) => match session.aggregate_bytes.checked_add(command_bytes.len()) {
                    Some(value) => (Some(value), false),
                    None => (None, true),
                },
                None => (None, false),
            },
        };
        if accounting_overflow
            || command.envelope().is_some()
                && accounted_request
                    .is_some_and(|total| total > qk_card_protocol::MAX_AGGREGATE_BYTES)
        {
            self.terminate();
            let error = ProtocolError::SessionStateRejected;
            let _ = qk_card_protocol::encode_rejection(error, output);
            return Err(error);
        }
        let response_budget = accounted_request
            .and_then(|used| qk_card_protocol::MAX_AGGREGATE_BYTES.checked_sub(used));
        if response_budget.is_some_and(|budget| {
            fixed_success_response_bytes(&command).is_some_and(|length| length > budget)
        }) {
            self.terminate();
            let error = ProtocolError::SessionStateRejected;
            let _ = qk_card_protocol::encode_rejection(error, output);
            return Err(error);
        }
        self.response_budget = response_budget;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if self.take_fault(FaultPoint::CaughtUnwind) {
                std::panic::resume_unwind(Box::new("qk-card-model injected caught unwind"));
            }
            self.execute_command(command, output)
        }));
        self.response_budget = None;
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                self.terminate();
                output.fill(0);
                std::panic::resume_unwind(payload);
            }
        };
        match result {
            Ok(length) => {
                if let Some(request_total) = accounted_request {
                    let total = request_total.checked_add(length);
                    if total.is_none_or(|value| value > qk_card_protocol::MAX_AGGREGATE_BYTES) {
                        self.terminate();
                        output.fill(0);
                        let error = ProtocolError::SessionStateRejected;
                        let _ = qk_card_protocol::encode_rejection(error, output);
                        return Err(error);
                    }
                    if let (Some(session), Some(value)) = (&mut self.session, total) {
                        session.aggregate_bytes = value;
                    }
                }
                Ok(length)
            }
            Err(error) => {
                let _ = qk_card_protocol::encode_rejection(error, output);
                Err(error)
            }
        }
    }

    pub fn inject_fault(&mut self, fault: FaultPoint) {
        if fault == FaultPoint::CorruptCommittedDigest {
            if let Storage::Committed(committed) = &mut self.storage {
                committed.digest.as_mut_bytes()[0] ^= 1;
                return;
            }
        }
        self.pending_fault = Some(fault);
    }

    /// Make the next successful deterministic fixture signature use the valid
    /// high-S sibling. This is a HOST-test seam, not modeled card policy.
    pub fn emit_high_s_once(&mut self) {
        self.next_signature_high_s = true;
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn set_aggregate_bytes_for_test(&mut self, value: usize) {
        if let Some(session) = &mut self.session {
            session.aggregate_bytes = value;
        }
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn aggregate_bytes_for_test(&self) -> Option<usize> {
        self.session.as_ref().map(|session| session.aggregate_bytes)
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn set_command_count_for_test(&mut self, value: u16) {
        if let Some(session) = &mut self.session {
            session.command_count = value;
        }
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn set_signature_count_for_test(&mut self, value: u8) {
        if let Some(session) = &mut self.session {
            session.sign_count = value;
        }
    }

    pub fn open(
        &mut self,
        version: u8,
        mode: ModelMode,
        session_id: [u8; 16],
    ) -> Result<(), ModelError> {
        if version != 1 {
            return self.reject(ModelError::ProtocolVersionMismatch);
        }
        if !self.selected || self.session.is_some() {
            return self.reject(ModelError::SessionStateRejected);
        }
        let permitted = match &self.storage {
            Storage::Unprovisioned => matches!(mode, ModelMode::Setup | ModelMode::KitRestore),
            Storage::Staging(staging) => staging.mode == mode,
            Storage::Committed(_) => true,
            Storage::RetiredError => true,
        };
        if !permitted {
            return self.reject(ModelError::LifecycleRejected);
        }
        if let Storage::Committed(committed) = &self.storage {
            let mut digest = wipe::WipingArray::<32>::zeroed();
            crypto::record_digest(committed.record.as_bytes(), digest.as_mut_array());
            let matches = digest.as_array() == committed.digest.as_bytes();
            if !matches {
                return self.integrity_failure();
            }
        }
        self.session = Some(Session::new(mode, session_id));
        Ok(())
    }

    pub fn info(&mut self, id: &[u8; 16], sequence: u32) -> Result<CardInfo, ModelError> {
        self.advance(id, sequence)?;
        let (profile, instance, wallet, fingerprint, xpub) = match &self.storage {
            Storage::Committed(value) => {
                let record = value.record.as_bytes();
                let mut instance = [0u8; 16];
                instance.copy_from_slice(
                    &record[crypto::INSTANCE_OFFSET..crypto::INSTANCE_OFFSET + 16],
                );
                let mut wallet = [0u8; 32];
                wallet.copy_from_slice(&record[crypto::WALLET_OFFSET..crypto::WALLET_OFFSET + 32]);
                let mut fp = [0u8; 4];
                fp.copy_from_slice(
                    &record[crypto::FINGERPRINT_OFFSET..crypto::FINGERPRINT_OFFSET + 4],
                );
                (
                    record[crypto::PROFILE_OFFSET],
                    instance,
                    wallet,
                    fp,
                    value.account_xpub,
                )
            }
            _ => (0, [0; 16], [0; 32], [0; 4], [0; EXTENDED_KEY_BYTES]),
        };
        Ok(CardInfo {
            protocol_version: 1,
            record_version: 1,
            lifecycle: self.lifecycle(),
            profile,
            role: 2,
            instance_id: instance,
            wallet_id: wallet,
            origin_fingerprint: fingerprint,
            account_xpub: xpub,
            allowed_operations: self.allowed_mask(),
        })
    }

    pub fn begin_provision(
        &mut self,
        id: &[u8; 16],
        sequence: u32,
        ordinal: u8,
        nonce: [u8; 12],
    ) -> Result<(), ModelError> {
        self.advance(id, sequence)?;
        let mode = self.mode()?;
        if !matches!(mode, ModelMode::Setup | ModelMode::KitRestore) {
            return self.reject(ModelError::ModeOrOperationRejected);
        }
        if !matches!(self.storage, Storage::Unprovisioned | Storage::Staging(_)) {
            return self.reject(ModelError::LifecycleRejected);
        }
        let valid = match mode {
            ModelMode::Setup => matches!(ordinal, 1 | 2),
            ModelMode::KitRestore => ordinal == 3,
            _ => false,
        };
        if !valid {
            return self.reject(ModelError::ProvisioningOrderRejected);
        }
        self.require_response_budget(23)?;
        self.check_persistent_fault()?;
        self.storage = Storage::Staging(Staging {
            mode,
            ordinal,
            nonce,
            record: wipe::Secret::zeroed(),
            filled: 0,
        });
        Ok(())
    }

    pub fn write_chunk(
        &mut self,
        id: &[u8; 16],
        sequence: u32,
        offset: u16,
        bytes: &[u8],
    ) -> Result<u16, ModelError> {
        self.advance(id, sequence)?;
        const STEPS: [(usize, usize); 5] =
            [(0, 192), (192, 192), (384, 192), (576, 192), (768, 13)];
        let (expected_offset, expected_len) = match &self.storage {
            Storage::Staging(staging) => {
                let Some(step) = STEPS
                    .iter()
                    .copied()
                    .find(|(start, _)| *start == staging.filled)
                else {
                    return self.reject(ModelError::ProvisioningOrderRejected);
                };
                step
            }
            _ => return self.reject(ModelError::LifecycleRejected),
        };
        if usize::from(offset) != expected_offset || bytes.len() != expected_len {
            return self.reject(ModelError::ProvisioningOrderRejected);
        }
        self.require_response_budget(25)?;
        let end = expected_offset + expected_len;
        let Storage::Staging(staging) = &mut self.storage else {
            return self.integrity_failure();
        };
        staging.record.as_mut_bytes()[expected_offset..end].copy_from_slice(bytes);
        staging.filled = end;
        self.check_persistent_fault()?;
        Ok(end as u16)
    }

    pub fn abort(&mut self, id: &[u8; 16], sequence: u32) -> Result<(), ModelError> {
        self.advance(id, sequence)?;
        if !matches!(self.storage, Storage::Staging(_)) {
            return self.reject(ModelError::LifecycleRejected);
        }
        self.require_response_budget(23)?;
        self.check_persistent_fault()?;
        self.storage = Storage::Unprovisioned;
        self.terminate();
        Ok(())
    }

    pub fn commit(&mut self, id: &[u8; 16], sequence: u32) -> Result<(), ModelError> {
        self.advance(id, sequence)?;
        let staging_complete = match &self.storage {
            Storage::Staging(staging) => staging.filled == RECORD_BYTES,
            _ => return self.reject(ModelError::LifecycleRejected),
        };
        if !staging_complete {
            return self.reject(ModelError::ProvisioningOrderRejected);
        }
        self.require_response_budget(23)?;
        let mut xpub = wipe::WipingArray::<EXTENDED_KEY_BYTES>::zeroed();
        {
            let Storage::Staging(staging) = &self.storage else {
                return self.reject(ModelError::InternalIntegrityFailure);
            };
            match crypto::validate_and_derive_xpub(
                staging.record.as_bytes(),
                staging.ordinal,
                &staging.nonce,
                xpub.as_mut_array(),
            ) {
                Ok(()) => {}
                Err(crypto::CryptoError::Record) => return self.reject(ModelError::RecordRejected),
                Err(crypto::CryptoError::Wallet) => {
                    return self.reject(ModelError::WalletBindingRejected)
                }
                Err(crypto::CryptoError::Child) => {
                    return self.reject(ModelError::ChildDerivationRejected)
                }
                Err(crypto::CryptoError::Native) => {
                    return self.reject(ModelError::CryptographicOperationRejected)
                }
            }
        }
        if self.take_fault(FaultPoint::CryptographicOperation) {
            return self.reject(ModelError::CryptographicOperationRejected);
        }
        if matches!(
            self.pending_fault,
            Some(FaultPoint::PersistentWrite | FaultPoint::Transaction)
        ) {
            return self.integrity_failure();
        }
        let Storage::Staging(staging) = &self.storage else {
            return self.integrity_failure();
        };
        let mut raw_record = wipe::WipingArray::<RECORD_BYTES>::zeroed();
        raw_record
            .as_mut_slice()
            .copy_from_slice(staging.record.as_bytes());
        let mut raw_digest = wipe::WipingArray::<32>::zeroed();
        crypto::record_digest(raw_record.as_array(), raw_digest.as_mut_array());
        let record = wipe::Secret::from_source(raw_record.as_mut_array());
        let digest = wipe::Secret::from_source(raw_digest.as_mut_array());
        let mut committed_xpub = [0u8; EXTENDED_KEY_BYTES];
        committed_xpub.copy_from_slice(xpub.as_slice());
        self.storage = Storage::Committed(Committed {
            record,
            account_xpub: committed_xpub,
            digest,
        });
        self.pending_fault = None;
        self.terminate();
        Ok(())
    }

    pub fn read_descriptor(
        &mut self,
        id: &[u8; 16],
        sequence: u32,
        selector: u8,
        offset: u16,
        output: &mut [u8; 192],
    ) -> Result<usize, ModelError> {
        self.advance(id, sequence)?;
        let step = self
            .session
            .as_ref()
            .map(|s| s.read_step)
            .ok_or(ModelError::SessionStateRejected)?;
        let expected = [
            (1, 0usize, 192usize),
            (1, 192, 114),
            (2, 0, 192),
            (2, 192, 114),
        ];
        let Some(&(want_selector, want_offset, len)) = expected.get(usize::from(step)) else {
            return self.reject(ModelError::ModeOrOperationRejected);
        };
        if selector != want_selector || usize::from(offset) != want_offset {
            return self.reject(ModelError::ModeOrOperationRejected);
        }
        let Storage::Committed(committed) = &self.storage else {
            return self.reject(ModelError::LifecycleRejected);
        };
        let base = if selector == 1 {
            crypto::RECEIVE_OFFSET
        } else {
            crypto::CHANGE_OFFSET
        };
        output.fill(0);
        output[..len].copy_from_slice(
            &committed.record.as_bytes()[base + want_offset..base + want_offset + len],
        );
        if let Some(session) = &mut self.session {
            session.read_step = session.read_step.saturating_add(1);
        }
        Ok(len)
    }

    pub fn export_a2(
        &mut self,
        id: &[u8; 16],
        sequence: u32,
        purpose: u8,
        output: &mut [u8; 32],
    ) -> Result<(), ModelError> {
        self.advance(id, sequence)?;
        let Some(session) = &self.session else {
            return self.reject(ModelError::SessionStateRejected);
        };
        let expected = match session.mode {
            ModelMode::Setup => Some(1),
            ModelMode::Normal => Some(2),
            ModelMode::Rescue => Some(3),
            ModelMode::KitRestore => None,
        };
        if expected != Some(purpose) || session.a2_exported {
            return self.reject(ModelError::ModeOrOperationRejected);
        }
        let Storage::Committed(committed) = &self.storage else {
            return self.reject(ModelError::LifecycleRejected);
        };
        output.copy_from_slice(
            &committed.record.as_bytes()[crypto::A2_OFFSET..crypto::A2_OFFSET + 32],
        );
        if let Some(session) = &mut self.session {
            session.a2_exported = true;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_digest(
        &mut self,
        id: &[u8; 16],
        sequence: u32,
        wallet_id: &[u8; 32],
        review_hash: &[u8; 32],
        input_index: u32,
        branch: u8,
        child_index: u32,
        digest: &[u8; 32],
    ) -> Result<SignReply, ModelError> {
        self.advance(id, sequence)?;
        let Some(session) = &self.session else {
            return self.reject(ModelError::SessionStateRejected);
        };
        let mode = session.mode;
        let sign_count = session.sign_count;
        let last_input = session.last_input;
        let binding_mismatch = match (&session.signing_wallet, &session.signing_review) {
            (Some(bound_wallet), Some(bound_review)) => {
                bound_wallet.as_bytes() != wallet_id || bound_review.as_bytes() != review_hash
            }
            _ => false,
        };
        if !matches!(mode, ModelMode::Normal | ModelMode::Rescue) {
            return self.reject(ModelError::ModeOrOperationRejected);
        }
        if sign_count >= MAX_SIGNATURES {
            return self.reject(ModelError::ModeOrOperationRejected);
        }
        let committed_wallet_matches = match &self.storage {
            Storage::Committed(committed) => {
                committed.record.as_bytes()[crypto::WALLET_OFFSET..crypto::WALLET_OFFSET + 32]
                    == wallet_id[..]
            }
            _ => return self.reject(ModelError::LifecycleRejected),
        };
        if !committed_wallet_matches {
            return self.reject(ModelError::WalletBindingRejected);
        }
        if branch > 1 || child_index > 65_535 {
            return self.reject(ModelError::DerivationPathRejected);
        }
        if self.take_fault(FaultPoint::ChildDerivation) {
            return self.reject(ModelError::ChildDerivationRejected);
        }
        let inject_unwind = self.take_fault(FaultPoint::InteriorCryptoUnwind);
        let derived = {
            let Storage::Committed(committed) = &self.storage else {
                return self.reject(ModelError::InternalIntegrityFailure);
            };
            crypto::derive_signing_child(
                committed.record.as_bytes(),
                branch,
                child_index,
                inject_unwind,
            )
        };
        if matches!(&derived, Err(crypto::CryptoError::Child)) {
            return self.reject(ModelError::ChildDerivationRejected);
        }
        if binding_mismatch || last_input.is_some_and(|last| input_index <= last) {
            return self.reject(ModelError::SigningBindingRejected);
        }
        if self.take_fault(FaultPoint::CryptographicOperation) {
            return self.reject(ModelError::CryptographicOperationRejected);
        }
        let child = match derived {
            Ok(child) => child,
            Err(_) => return self.reject(ModelError::CryptographicOperationRejected),
        };
        let mut public_key = wipe::WipingArray::<33>::zeroed();
        let mut der = wipe::WipingArray::<MAX_DER_BYTES>::zeroed();
        let mut der_len = match crypto::sign_derived_child(
            child,
            digest,
            public_key.as_mut_array(),
            der.as_mut_array(),
        ) {
            Ok(len) => len,
            Err(crypto::CryptoError::Child) => {
                return self.reject(ModelError::ChildDerivationRejected)
            }
            Err(_) => return self.reject(ModelError::CryptographicOperationRejected),
        };
        if self.next_signature_high_s {
            let mut high = wipe::WipingArray::<MAX_DER_BYTES>::zeroed();
            der_len = match crypto::high_s_sibling(&der.as_slice()[..der_len], high.as_mut_array())
            {
                Ok(len) => len,
                Err(_) => {
                    return self.reject(ModelError::CryptographicOperationRejected);
                }
            };
            wipe::bytes(der.as_mut_slice());
            der.as_mut_slice().copy_from_slice(high.as_slice());
            self.next_signature_high_s = false;
        }
        self.require_response_budget(ENVELOPED_RESPONSE_BYTES + 70 + der_len)?;
        if let Some(session) = &mut self.session {
            if session.signing_wallet.is_none() {
                let mut wallet = *wallet_id;
                session.signing_wallet = Some(wipe::Secret::from_source(&mut wallet));
                let mut review = *review_hash;
                session.signing_review = Some(wipe::Secret::from_source(&mut review));
            }
            session.sign_count = session.sign_count.saturating_add(1);
            session.last_input = Some(input_index);
        }
        let mut reply_public = [0u8; 33];
        reply_public.copy_from_slice(public_key.as_slice());
        let mut reply_der = [0u8; MAX_DER_BYTES];
        reply_der.copy_from_slice(der.as_slice());
        Ok(SignReply {
            review_hash: *review_hash,
            input_index,
            public_key: reply_public,
            der: reply_der,
            der_len,
        })
    }

    fn mode(&self) -> Result<ModelMode, ModelError> {
        self.session
            .as_ref()
            .map(|session| session.mode)
            .ok_or(ModelError::SessionStateRejected)
    }

    fn allowed_mask(&self) -> u16 {
        let Some(session) = &self.session else {
            return 0;
        };
        match (&self.storage, session.mode) {
            (Storage::Unprovisioned, ModelMode::Setup | ModelMode::KitRestore) => 0x0011,
            (Storage::Staging(staging), _) if staging.filled == RECORD_BYTES => 0x00d1,
            (Storage::Staging(_), _) => 0x00b1,
            (Storage::Committed(_), ModelMode::Setup) => 0x0007,
            (Storage::Committed(_), ModelMode::Normal | ModelMode::Rescue) => 0x000f,
            (Storage::Committed(_), ModelMode::KitRestore) => 0x0003,
            (Storage::RetiredError, _) => 0x0001,
            _ => 0,
        }
    }

    fn advance(&mut self, id: &[u8; 16], sequence: u32) -> Result<(), ModelError> {
        let Some(session) = &mut self.session else {
            return self.reject(ModelError::SessionStateRejected);
        };
        if session.command_count >= MAX_COMMANDS {
            return self.reject(ModelError::SessionStateRejected);
        }
        if &session.id != id {
            return self.reject(ModelError::SessionIdMismatch);
        }
        if sequence != session.next_sequence {
            return self.reject(ModelError::SequenceRejected);
        }
        if sequence == u32::MAX {
            return self.reject(ModelError::SessionStateRejected);
        }
        session.next_sequence = session.next_sequence.saturating_add(1);
        session.command_count = session.command_count.saturating_add(1);
        Ok(())
    }

    fn check_persistent_fault(&mut self) -> Result<(), ModelError> {
        if matches!(
            self.pending_fault,
            Some(FaultPoint::PersistentWrite | FaultPoint::Transaction)
        ) {
            self.integrity_failure()
        } else {
            Ok(())
        }
    }

    fn take_fault(&mut self, fault: FaultPoint) -> bool {
        if self.pending_fault == Some(fault) {
            self.pending_fault = None;
            true
        } else {
            false
        }
    }

    fn require_response_budget(&mut self, bytes: usize) -> Result<(), ModelError> {
        if self.response_budget.is_some_and(|budget| bytes > budget) {
            self.reject(ModelError::SessionStateRejected)
        } else {
            Ok(())
        }
    }

    fn integrity_failure<T>(&mut self) -> Result<T, ModelError> {
        self.pending_fault = None;
        self.storage = Storage::RetiredError;
        self.terminate();
        Err(ModelError::InternalIntegrityFailure)
    }

    fn reject<T>(&mut self, error: ModelError) -> Result<T, ModelError> {
        self.terminate();
        Err(error)
    }

    fn terminate(&mut self) {
        self.session = None;
        self.selected = false;
    }

    fn execute_command(
        &mut self,
        command: CommandRef<'_>,
        output: &mut [u8; qk_card_protocol::MAX_RESPONSE_BYTES],
    ) -> Result<usize, ProtocolError> {
        match command {
            CommandRef::Select => {
                self.select(true).map_err(protocol_error)?;
                encode_success(None, &[], output)
            }
            CommandRef::OpenSession { mode, session_id } => {
                self.open(1, mode, *session_id).map_err(protocol_error)?;
                encode_success(Some(EnvelopeRef::new(session_id, 0)), &[], output)
            }
            CommandRef::GetInfo { envelope } => {
                let info = self
                    .info(envelope.session_id(), envelope.sequence())
                    .map_err(protocol_error)?;
                let mut tail = wipe::WipingArray::<137>::zeroed();
                tail.as_mut_slice()[0] = info.protocol_version;
                tail.as_mut_slice()[1] = info.record_version;
                tail.as_mut_slice()[2] = info.lifecycle.byte();
                tail.as_mut_slice()[3] = info.profile;
                tail.as_mut_slice()[4] = info.role;
                tail.as_mut_slice()[5..21].copy_from_slice(&info.instance_id);
                tail.as_mut_slice()[21..53].copy_from_slice(&info.wallet_id);
                tail.as_mut_slice()[53..57].copy_from_slice(&info.origin_fingerprint);
                tail.as_mut_slice()[57..135].copy_from_slice(&info.account_xpub);
                tail.as_mut_slice()[135..137]
                    .copy_from_slice(&info.allowed_operations.to_be_bytes());
                encode_success(Some(envelope), tail.as_slice(), output)
            }
            CommandRef::ReadDChunk {
                envelope,
                selector,
                offset,
            } => {
                let mut descriptor = wipe::WipingArray::<192>::zeroed();
                let len = self
                    .read_descriptor(
                        envelope.session_id(),
                        envelope.sequence(),
                        selector.byte(),
                        offset,
                        descriptor.as_mut_array(),
                    )
                    .map_err(protocol_error)?;
                let mut tail = wipe::WipingArray::<195>::zeroed();
                tail.as_mut_slice()[0] = selector.byte();
                tail.as_mut_slice()[1..3].copy_from_slice(&offset.to_be_bytes());
                tail.as_mut_slice()[3..3 + len].copy_from_slice(&descriptor.as_slice()[..len]);
                encode_success(Some(envelope), &tail.as_slice()[..3 + len], output)
            }
            CommandRef::ExportA2 { envelope, purpose } => {
                let mut a2 = wipe::WipingArray::<32>::zeroed();
                self.export_a2(
                    envelope.session_id(),
                    envelope.sequence(),
                    purpose.byte(),
                    a2.as_mut_array(),
                )
                .map_err(protocol_error)?;
                let mut tail = wipe::WipingArray::<33>::zeroed();
                tail.as_mut_slice()[0] = purpose.byte();
                tail.as_mut_slice()[1..].copy_from_slice(a2.as_slice());
                encode_success(Some(envelope), tail.as_slice(), output)
            }
            CommandRef::SignDigest {
                envelope,
                wallet_id,
                review_hash,
                input_index,
                branch,
                child_index,
                digest,
            } => {
                let reply = self
                    .sign_digest(
                        envelope.session_id(),
                        envelope.sequence(),
                        wallet_id,
                        review_hash,
                        input_index,
                        branch,
                        child_index,
                        digest,
                    )
                    .map_err(protocol_error)?;
                let mut tail = wipe::WipingArray::<142>::zeroed();
                tail.as_mut_slice()[..32].copy_from_slice(reply.review_hash());
                tail.as_mut_slice()[32..36].copy_from_slice(&reply.input_index().to_be_bytes());
                tail.as_mut_slice()[36..69].copy_from_slice(reply.public_key());
                tail.as_mut_slice()[69] = reply.der().len() as u8;
                let end = 70 + reply.der().len();
                tail.as_mut_slice()[70..end].copy_from_slice(reply.der());
                encode_success(Some(envelope), &tail.as_slice()[..end], output)
            }
            CommandRef::BeginProvision {
                envelope,
                ordinal,
                provisioning_nonce,
            } => {
                self.begin_provision(
                    envelope.session_id(),
                    envelope.sequence(),
                    ordinal,
                    *provisioning_nonce,
                )
                .map_err(protocol_error)?;
                encode_success(Some(envelope), &[], output)
            }
            CommandRef::WriteChunk {
                envelope,
                offset,
                bytes,
            } => {
                let next = self
                    .write_chunk(envelope.session_id(), envelope.sequence(), offset, bytes)
                    .map_err(protocol_error)?;
                encode_success(Some(envelope), &next.to_be_bytes(), output)
            }
            CommandRef::Commit { envelope } => {
                self.commit(envelope.session_id(), envelope.sequence())
                    .map_err(protocol_error)?;
                encode_success(Some(envelope), &[], output)
            }
            CommandRef::Abort { envelope } => {
                self.abort(envelope.session_id(), envelope.sequence())
                    .map_err(protocol_error)?;
                encode_success(Some(envelope), &[], output)
            }
        }
    }
}

fn protocol_error(error: ModelError) -> ProtocolError {
    match error {
        ModelError::ContactInterfaceRequired => ProtocolError::ContactInterfaceRequired,
        ModelError::ProtocolVersionMismatch => ProtocolError::ProtocolVersionMismatch,
        ModelError::SessionStateRejected => ProtocolError::SessionStateRejected,
        ModelError::SessionIdMismatch => ProtocolError::SessionIdMismatch,
        ModelError::SequenceRejected => ProtocolError::SequenceRejected,
        ModelError::ModeOrOperationRejected => ProtocolError::ModeOrOperationRejected,
        ModelError::LifecycleRejected => ProtocolError::LifecycleRejected,
        ModelError::ProvisioningOrderRejected => ProtocolError::ProvisioningOrderRejected,
        ModelError::RecordRejected => ProtocolError::RecordRejected,
        ModelError::WalletBindingRejected => ProtocolError::WalletBindingRejected,
        ModelError::DerivationPathRejected => ProtocolError::DerivationPathRejected,
        ModelError::ChildDerivationRejected => ProtocolError::ChildDerivationRejected,
        ModelError::SigningBindingRejected => ProtocolError::SigningBindingRejected,
        ModelError::CryptographicOperationRejected => ProtocolError::CryptographicOperationRejected,
        ModelError::InternalIntegrityFailure => ProtocolError::InternalIntegrityFailure,
    }
}

fn encode_success(
    envelope: Option<EnvelopeRef<'_>>,
    tail: &[u8],
    output: &mut [u8; qk_card_protocol::MAX_RESPONSE_BYTES],
) -> Result<usize, ProtocolError> {
    qk_card_protocol::encode_success(envelope, tail, output)
        .map_err(|_| ProtocolError::InternalIntegrityFailure)
}

fn fixed_success_response_bytes(command: &CommandRef<'_>) -> Option<usize> {
    match command {
        CommandRef::Select => None,
        CommandRef::OpenSession { .. }
        | CommandRef::BeginProvision { .. }
        | CommandRef::Commit { .. }
        | CommandRef::Abort { .. } => Some(ENVELOPED_RESPONSE_BYTES),
        CommandRef::GetInfo { .. } => Some(ENVELOPED_RESPONSE_BYTES + 137),
        CommandRef::ReadDChunk { offset, .. } => {
            let descriptor_bytes = if *offset == 0 { 192 } else { 114 };
            Some(ENVELOPED_RESPONSE_BYTES + 3 + descriptor_bytes)
        }
        CommandRef::ExportA2 { .. } => Some(ENVELOPED_RESPONSE_BYTES + 33),
        CommandRef::SignDigest { .. } => None,
        CommandRef::WriteChunk { .. } => Some(ENVELOPED_RESPONSE_BYTES + 2),
    }
}
