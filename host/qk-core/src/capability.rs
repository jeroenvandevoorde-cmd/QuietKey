//! Typed HOST mock capabilities owned by the trusted process shell.
//!
//! These mocks expose only the three QK-DEC-144 capability shapes. They do
//! not model a renderer, scan codes, APDUs, card data, persistence, or real
//! devices.

#![forbid(unsafe_code)]

use crate::error::CoreError;

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
}

/// Presence fact exposed by the card-slot mock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardPresence {
    Absent,
    Present,
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

/// Typed card-slot mock exposing only presence and removal facts.
pub struct MockCardSlot {
    presence: CardPresence,
    fail_next: bool,
}

impl MockCardSlot {
    pub const fn new(presence: CardPresence) -> Self {
        Self {
            presence,
            fail_next: false,
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
