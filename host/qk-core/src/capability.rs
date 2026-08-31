//! Typed HOST mock capabilities owned by the trusted process shell.
//!
//! These mocks expose only the three process-shell capability shapes. The
//! card seam records public v2 setup bindings but models no secret transfer,
//! renderer, scan code, APDU, persistence, or real device.

#![forbid(unsafe_code)]

use crate::error::CoreError;
use crate::wipe::{self, WipingArray, WipingValueVec, WipingVec};

const MAX_NORMAL_INPUTS: usize = 100;
const MAX_DER_SIGNATURE_BYTES: usize = 72;

/// Exact nineteen-key logical P0.1 keypad vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeypadKey {
    Seven,
    EightUp,
    Nine,
    CeDelete,
    CancelBack,
    FourLeft,
    Five,
    SixRight,
    Multiply,
    Divide,
    One,
    TwoDown,
    Three,
    Minus,
    Percent,
    Zero,
    Decimal,
    Plus,
    EqualsConfirmEnter,
}

/// Nonsecret shell-lifecycle screen selected by qk-core.
///
/// No variant carries text, transported bytes, a wallet fact, or a failure
/// reason. The display mock retains at most one value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreScreen {
    Opening,
    Ready,
    IngressBeginPending,
    IngressReadReady,
    IngressReadPending,
    IngressComplete,
    Closing,
    Closed,
    Terminated,
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
    NormalStart,
    ProfileBinding,
    NormalTransport,
    PsbtIntake,
    FactorB,
    A1Intake,
    FactorA1,
    NormalValidation,
    ReviewOverview,
    ReviewArithmetic,
    ReviewRecipient,
    ReviewChange,
    ReviewOpReturn,
    ReviewLocktime,
    ReviewSequence,
    ReviewFeePolicy,
    ReviewFeeFacts,
    ReviewWarning,
    FinalApproval,
    ApprovalHeld,
    Revalidation,
    TerminalASigning,
    CardBSigning,
    Finalization,
    AwaitingExportAction,
    TransactionResult,
    CompletedWiped,
}

/// Presence fact exposed by the card-slot mock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardPresence {
    Absent,
    Present,
}

/// Exact setup-time mock card instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardInstanceV2 {
    Required,
    Spare,
}

impl CardInstanceV2 {
    /// Exact QK-DEC-145 public instance tag.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Required => 0x01,
            Self::Spare => 0x02,
        }
    }
}

/// Public-only setup binding presented to the card mock.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CardBPublicBindingV2 {
    instance: CardInstanceV2,
    role: u8,
    wallet_id: [u8; 32],
    account_xpub: [u8; 111],
}

impl CardBPublicBindingV2 {
    /// Bind one role-B account to one exact wallet and mock card instance.
    pub const fn new(
        instance: CardInstanceV2,
        wallet_id: [u8; 32],
        account_xpub: [u8; 111],
    ) -> Self {
        Self {
            instance,
            role: 0x02,
            wallet_id,
            account_xpub,
        }
    }

    pub const fn instance(&self) -> CardInstanceV2 {
        self.instance
    }

    pub const fn role(&self) -> u8 {
        self.role
    }

    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn account_xpub(&self) -> [u8; 111] {
        self.account_xpub
    }
}

/// Closed public-card-mock rejection surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardMockErrorV2 {
    CardAbsent,
    CardInstanceAlreadyProvisioned,
    CardBindingMismatch,
}

/// Closed construction and access failures for the normal-flow card mock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalCardMockErrorV2 {
    SignatureTooLong,
    TooManySignatures,
    CardAbsent,
    CardAccessFailed,
    CardDataUnavailable,
}

impl NormalCardMockErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignatureTooLong => "SignatureTooLong",
            Self::TooManySignatures => "TooManySignatures",
            Self::CardAbsent => "CardAbsent",
            Self::CardAccessFailed => "CardAccessFailed",
            Self::CardDataUnavailable => "CardDataUnavailable",
        }
    }
}

/// One DER-only mock role-B response bound to one input index.
///
/// Construction consumes and clears the caller's mutable scratch bytes. The
/// retained allocation, including spare capacity, is cleared on drop.
pub struct NormalCardBSignatureV2 {
    input_index: u32,
    der: WipingVec,
}

impl NormalCardBSignatureV2 {
    pub fn try_new(
        input_index: u32,
        der_signature: &mut [u8],
    ) -> Result<Self, NormalCardMockErrorV2> {
        if der_signature.len() > MAX_DER_SIGNATURE_BYTES {
            wipe::bytes(der_signature);
            return Err(NormalCardMockErrorV2::SignatureTooLong);
        }
        let copied = WipingVec::try_copy(der_signature);
        wipe::bytes(der_signature);
        let der = copied.map_err(|_| NormalCardMockErrorV2::CardDataUnavailable)?;
        Ok(Self { input_index, der })
    }

    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    pub fn der_signature(&self) -> &[u8] {
        self.der.as_slice()
    }
}

/// One authenticated HOST mock card-B factor for a normal A1+B session.
///
/// Descriptor bytes, wallet identity and account xpub are public facts. A2 is
/// a fixed secret owner with no public accessor. The value carries only
/// preloaded DER responses; it exposes no signing operation or B secret.
pub struct NormalCardBDataV2 {
    descriptors: [[u8; 306]; 2],
    wallet_id: [u8; 32],
    account_xpub: [u8; 111],
    a2: WipingArray<32>,
    signatures: WipingValueVec<NormalCardBSignatureV2>,
}

impl NormalCardBDataV2 {
    pub fn try_new(
        descriptors: [[u8; 306]; 2],
        wallet_id: [u8; 32],
        account_xpub: [u8; 111],
        a2: &mut [u8; 32],
        signatures: Vec<NormalCardBSignatureV2>,
    ) -> Result<Self, NormalCardMockErrorV2> {
        let a2 = WipingArray::take(a2);
        let signatures = WipingValueVec::from_vec(signatures);
        if signatures.len() > MAX_NORMAL_INPUTS {
            drop(a2);
            drop(signatures);
            return Err(NormalCardMockErrorV2::TooManySignatures);
        }
        Ok(Self {
            descriptors,
            wallet_id,
            account_xpub,
            a2,
            signatures,
        })
    }

    pub const fn descriptors(&self) -> &[[u8; 306]; 2] {
        &self.descriptors
    }

    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn account_xpub(&self) -> &[u8; 111] {
        &self.account_xpub
    }

    pub fn signatures(&self) -> &[NormalCardBSignatureV2] {
        self.signatures.as_slice()
    }

    pub(crate) const fn a2(&self) -> &[u8; 32] {
        self.a2.as_array()
    }
}

impl CardMockErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::CardAbsent => "CardAbsent",
            Self::CardInstanceAlreadyProvisioned => "CardInstanceAlreadyProvisioned",
            Self::CardBindingMismatch => "CardBindingMismatch",
        }
    }
}

/// Typed display mock retaining only the current nonsecret screen.
pub struct MockDisplay {
    current: Option<CoreScreen>,
    fail_next: bool,
}

impl MockDisplay {
    pub const fn new() -> Self {
        Self {
            current: None,
            fail_next: false,
        }
    }

    /// Inject exactly one failure into the next display operation.
    pub fn inject_failure(&mut self) {
        self.fail_next = true;
    }

    /// Select one typed screen, retaining the old screen if the operation
    /// fails.
    pub fn show(&mut self, screen: CoreScreen) -> Result<(), CoreError> {
        if self.take_failure() {
            return Err(CoreError::DisplayFailed);
        }
        self.current = Some(screen);
        Ok(())
    }

    /// Clear the retained screen, retaining it if the operation fails.
    pub fn clear(&mut self) -> Result<(), CoreError> {
        if self.take_failure() {
            return Err(CoreError::DisplayFailed);
        }
        self.current = None;
        Ok(())
    }

    pub const fn current(&self) -> Option<CoreScreen> {
        self.current
    }

    fn take_failure(&mut self) -> bool {
        let failed = self.fail_next;
        self.fail_next = false;
        failed
    }
}

impl Default for MockDisplay {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed keypad mock. A caller may present only a logical P0.1 key.
pub struct MockKeypad {
    fail_next: bool,
}

impl MockKeypad {
    pub const fn new() -> Self {
        Self { fail_next: false }
    }

    /// Inject exactly one failure into the next keypad operation.
    pub fn inject_failure(&mut self) {
        self.fail_next = true;
    }

    /// Read one already-normalized logical key. There is no scan-code API.
    pub fn read(&mut self, key: KeypadKey) -> Result<KeypadKey, CoreError> {
        if self.take_failure() {
            return Err(CoreError::KeypadFailed);
        }
        Ok(key)
    }

    fn take_failure(&mut self) -> bool {
        let failed = self.fail_next;
        self.fail_next = false;
        failed
    }
}

impl Default for MockKeypad {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed card-slot mock exposing presence and public-only setup bindings.
pub struct MockCardSlot {
    presence: CardPresence,
    fail_next: bool,
    required_binding: Option<CardBPublicBindingV2>,
    spare_binding: Option<CardBPublicBindingV2>,
    normal_data: Option<NormalCardBDataV2>,
}

impl MockCardSlot {
    pub const fn new(presence: CardPresence) -> Self {
        Self {
            presence,
            fail_next: false,
            required_binding: None,
            spare_binding: None,
            normal_data: None,
        }
    }

    /// Construct a slot preloaded with one move-only authenticated mock
    /// factor. The factor can be consumed by exactly one normal session.
    pub fn with_normal_data(presence: CardPresence, normal_data: NormalCardBDataV2) -> Self {
        Self {
            presence,
            fail_next: false,
            required_binding: None,
            spare_binding: None,
            normal_data: Some(normal_data),
        }
    }

    /// Inject exactly one failure into the next card-slot operation.
    pub fn inject_failure(&mut self) {
        self.fail_next = true;
    }

    /// Observe the current presence fact. No card command or data can cross
    /// this boundary.
    pub fn observe(&mut self, presence: CardPresence) -> Result<CardPresence, CoreError> {
        if self.take_failure() {
            return Err(CoreError::CardFailed);
        }
        self.presence = presence;
        Ok(presence)
    }

    pub const fn presence(&self) -> CardPresence {
        self.presence
    }

    /// Record one exact public-only role-B setup binding.
    pub fn provision_b(&mut self, binding: CardBPublicBindingV2) -> Result<(), CardMockErrorV2> {
        if self.presence != CardPresence::Present {
            return Err(CardMockErrorV2::CardAbsent);
        }
        let destination = match binding.instance() {
            CardInstanceV2::Required => &mut self.required_binding,
            CardInstanceV2::Spare => &mut self.spare_binding,
        };
        if destination.is_some() {
            return Err(CardMockErrorV2::CardInstanceAlreadyProvisioned);
        }
        *destination = Some(binding);
        Ok(())
    }

    /// Require byte equality with the previously recorded public binding.
    pub fn verify_b(&mut self, binding: CardBPublicBindingV2) -> Result<(), CardMockErrorV2> {
        if self.presence != CardPresence::Present {
            return Err(CardMockErrorV2::CardAbsent);
        }
        let recorded = match binding.instance() {
            CardInstanceV2::Required => self.required_binding,
            CardInstanceV2::Spare => self.spare_binding,
        };
        if recorded == Some(binding) {
            Ok(())
        } else {
            Err(CardMockErrorV2::CardBindingMismatch)
        }
    }

    pub(crate) fn take_normal_data(&mut self) -> Result<NormalCardBDataV2, NormalCardMockErrorV2> {
        if self.take_failure() {
            return Err(NormalCardMockErrorV2::CardAccessFailed);
        }
        if self.presence != CardPresence::Present {
            return Err(NormalCardMockErrorV2::CardAbsent);
        }
        self.normal_data
            .take()
            .ok_or(NormalCardMockErrorV2::CardDataUnavailable)
    }

    fn take_failure(&mut self) -> bool {
        let failed = self.fail_next;
        self.fail_next = false;
        failed
    }
}

/// Exact, non-duplicable Display/Keypad/CardSlot grant set.
pub struct CoreDeviceGrants {
    display: MockDisplay,
    keypad: MockKeypad,
    card_slot: MockCardSlot,
}

impl CoreDeviceGrants {
    /// Validate a presented grant set before session identity minting.
    ///
    /// `has_unexpected` represents any capability other than the three typed
    /// arguments. Missing capabilities take precedence when both conditions
    /// are presented.
    pub fn validate(
        display: Option<MockDisplay>,
        keypad: Option<MockKeypad>,
        card_slot: Option<MockCardSlot>,
        has_unexpected: bool,
    ) -> Result<Self, CoreError> {
        let (Some(display), Some(keypad), Some(card_slot)) = (display, keypad, card_slot) else {
            return Err(CoreError::CapabilitiesMissing);
        };
        if has_unexpected {
            return Err(CoreError::CapabilitiesUnexpected);
        }
        Ok(Self {
            display,
            keypad,
            card_slot,
        })
    }

    pub const fn display(&self) -> &MockDisplay {
        &self.display
    }

    pub fn display_mut(&mut self) -> &mut MockDisplay {
        &mut self.display
    }

    pub fn keypad_mut(&mut self) -> &mut MockKeypad {
        &mut self.keypad
    }

    pub const fn card_slot(&self) -> &MockCardSlot {
        &self.card_slot
    }

    pub fn card_slot_mut(&mut self) -> &mut MockCardSlot {
        &mut self.card_slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KEYS: [KeypadKey; 19] = [
        KeypadKey::Seven,
        KeypadKey::EightUp,
        KeypadKey::Nine,
        KeypadKey::CeDelete,
        KeypadKey::CancelBack,
        KeypadKey::FourLeft,
        KeypadKey::Five,
        KeypadKey::SixRight,
        KeypadKey::Multiply,
        KeypadKey::Divide,
        KeypadKey::One,
        KeypadKey::TwoDown,
        KeypadKey::Three,
        KeypadKey::Minus,
        KeypadKey::Percent,
        KeypadKey::Zero,
        KeypadKey::Decimal,
        KeypadKey::Plus,
        KeypadKey::EqualsConfirmEnter,
    ];

    #[test]
    fn exact_grant_set_exposes_three_typed_capabilities() {
        let grants = CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Absent)),
            false,
        );
        assert!(grants.is_ok());
    }

    #[test]
    fn missing_precedes_unexpected_and_each_is_named() {
        let missing = CoreDeviceGrants::validate(
            None,
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Absent)),
            true,
        );
        assert!(matches!(missing, Err(CoreError::CapabilitiesMissing)));

        let unexpected = CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Absent)),
            true,
        );
        assert!(matches!(unexpected, Err(CoreError::CapabilitiesUnexpected)));
    }

    #[test]
    fn display_retains_one_screen_and_fault_is_one_shot() {
        let mut display = MockDisplay::new();
        assert!(display.show(CoreScreen::Opening).is_ok());
        display.inject_failure();
        assert!(matches!(
            display.show(CoreScreen::Ready),
            Err(CoreError::DisplayFailed)
        ));
        assert_eq!(display.current(), Some(CoreScreen::Opening));
        assert!(display.show(CoreScreen::Ready).is_ok());
        assert_eq!(display.current(), Some(CoreScreen::Ready));
        assert!(display.clear().is_ok());
        assert_eq!(display.current(), None);
    }

    #[test]
    fn keypad_accepts_exact_logical_vocabulary_and_fault_is_one_shot() {
        let mut keypad = MockKeypad::new();
        for key in ALL_KEYS {
            assert_eq!(keypad.read(key), Ok(key));
        }
        keypad.inject_failure();
        assert!(matches!(
            keypad.read(KeypadKey::CancelBack),
            Err(CoreError::KeypadFailed)
        ));
        assert_eq!(
            keypad.read(KeypadKey::CancelBack),
            Ok(KeypadKey::CancelBack)
        );
    }

    #[test]
    fn card_slot_exposes_only_presence_and_fault_retains_state() {
        let mut card = MockCardSlot::new(CardPresence::Present);
        card.inject_failure();
        assert!(matches!(
            card.observe(CardPresence::Absent),
            Err(CoreError::CardFailed)
        ));
        assert_eq!(card.presence(), CardPresence::Present);
        assert_eq!(card.observe(CardPresence::Absent), Ok(CardPresence::Absent));
        assert_eq!(card.presence(), CardPresence::Absent);
    }
}
