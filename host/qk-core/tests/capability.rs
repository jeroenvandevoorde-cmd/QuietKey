//! Typed capability grants and deliberately empty shell behavior.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreScreen, CoreSession, CoreState,
    Interruption, KeypadKey, MockCardSlot, MockDisplay, MockKeypad,
};

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

fn grants(presence: CardPresence) -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(presence)),
        false,
    )
    .expect("exact capability set")
}

#[test]
fn exact_grant_validation_and_each_mock_fault_are_named_and_one_shot() {
    assert!(matches!(
        CoreDeviceGrants::validate(
            None,
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Absent)),
            true,
        ),
        Err(CoreError::CapabilitiesMissing)
    ));
    assert!(matches!(
        CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Absent)),
            true,
        ),
        Err(CoreError::CapabilitiesUnexpected)
    ));

    let mut display = MockDisplay::new();
    display.show(CoreScreen::Opening).expect("opening screen");
    display.inject_failure();
    assert_eq!(
        display.show(CoreScreen::Ready),
        Err(CoreError::DisplayFailed)
    );
    assert_eq!(display.current(), Some(CoreScreen::Opening));
    display
        .show(CoreScreen::Ready)
        .expect("one-shot display fault");

    let mut keypad = MockKeypad::new();
    for key in ALL_KEYS {
        assert_eq!(keypad.read(key), Ok(key));
    }
    keypad.inject_failure();
    assert_eq!(keypad.read(KeypadKey::One), Err(CoreError::KeypadFailed));
    assert_eq!(keypad.read(KeypadKey::One), Ok(KeypadKey::One));

    let mut card = MockCardSlot::new(CardPresence::Present);
    card.inject_failure();
    assert_eq!(
        card.observe(CardPresence::Absent),
        Err(CoreError::CardFailed)
    );
    assert_eq!(card.presence(), CardPresence::Present);
    assert_eq!(card.observe(CardPresence::Absent), Ok(CardPresence::Absent));
}

#[test]
fn every_non_cancel_key_is_state_preserving_and_cancel_is_terminal() {
    let (mut session, _) =
        CoreSession::start(CoreMode::Setup, grants(CardPresence::Present)).expect("session");
    for key in ALL_KEYS
        .into_iter()
        .filter(|key| *key != KeypadKey::CancelBack)
    {
        assert_eq!(session.handle_key(key), Err(CoreError::NoActiveFlow));
        assert_eq!(session.state(), CoreState::Opening);
        assert_eq!(session.current_screen(), Some(CoreScreen::Opening));
    }

    assert_eq!(
        session.handle_key(KeypadKey::CancelBack),
        Ok(Interruption::Cancelled)
    );
    assert_eq!(session.state(), CoreState::Terminated);
    assert_eq!(session.terminal_reason(), Some(Interruption::Cancelled));
    assert_eq!(session.current_screen(), Some(CoreScreen::Terminated));
    assert_eq!(
        session.handle_key(KeypadKey::CancelBack),
        Err(CoreError::CoreTerminated)
    );
}

#[test]
fn card_presence_is_observable_but_removal_wipes_and_terminates() {
    let (mut session, _) =
        CoreSession::start(CoreMode::Kit, grants(CardPresence::Present)).expect("session");
    assert_eq!(
        session.observe_card(CardPresence::Present),
        Ok(CardPresence::Present)
    );
    assert_eq!(session.state(), CoreState::Opening);
    assert_eq!(
        session.observe_card(CardPresence::Absent),
        Ok(CardPresence::Absent)
    );
    assert_eq!(session.state(), CoreState::Terminated);
    assert_eq!(session.terminal_reason(), Some(Interruption::CardRemoved));
    assert_eq!(session.current_screen(), Some(CoreScreen::Terminated));
}
