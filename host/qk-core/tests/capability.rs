//! Typed capability grants and deliberately empty shell behavior.

use qk_core::{
    CardBPublicBindingV2, CardInstanceV2, CardMockErrorV2, CardPresence, CoreDeviceGrants,
    CoreError, CoreMode, CoreScreen, CoreSession, CoreState, Interruption, KeypadKey, MockCardSlot,
    MockDisplay, MockKeypad, NormalCardBDataV2, NormalCardBSignatureV2, NormalCardMockErrorV2,
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
fn every_ratified_kit_screen_is_a_typed_display_selection() {
    let screens = [
        CoreScreen::KitStart,
        CoreScreen::KitDoorSelection,
        CoreScreen::KitDoorConfirmation,
        CoreScreen::ScanKitShareOne,
        CoreScreen::ScanKitShareTwo,
        CoreScreen::CombineKitShares,
        CoreScreen::KitRestoreActionSelection,
        CoreScreen::CardRemainsConfirmation,
        CoreScreen::KitRestorePreparation,
        CoreScreen::KitRestoreHumanAssertion,
        CoreScreen::ProvisionReplacementB,
        CoreScreen::A1Reprint,
        CoreScreen::MandatoryFreshWalletMigration,
        CoreScreen::KitSpendTransaction,
        CoreScreen::KitSpendValidation,
        CoreScreen::KitSpendCompleteness,
        CoreScreen::KitSpendHumanAssertion,
    ];
    let mut display = MockDisplay::new();
    for screen in screens {
        display.show(screen).expect("typed Kit screen");
        assert_eq!(display.current(), Some(screen));
    }
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

fn binding(instance: CardInstanceV2, marker: u8) -> CardBPublicBindingV2 {
    CardBPublicBindingV2::new(instance, [marker; 32], [marker.wrapping_add(1); 111])
}

#[test]
fn card_mock_records_exactly_one_public_binding_per_instance() {
    let mut card = MockCardSlot::new(CardPresence::Present);
    let required = binding(CardInstanceV2::Required, 0x11);
    let spare = binding(CardInstanceV2::Spare, 0x22);

    assert_eq!(required.instance().wire_value(), 0x01);
    assert_eq!(spare.instance().wire_value(), 0x02);
    assert_eq!(required.role(), 0x02);
    assert_eq!(required.wallet_id(), [0x11; 32]);
    assert_eq!(required.account_xpub(), [0x12; 111]);

    assert_eq!(card.provision_b(required), Ok(()));
    assert_eq!(card.verify_b(required), Ok(()));
    assert_eq!(card.provision_b(spare), Ok(()));
    assert_eq!(card.verify_b(spare), Ok(()));
    assert_eq!(
        card.provision_b(required),
        Err(CardMockErrorV2::CardInstanceAlreadyProvisioned)
    );
    assert_eq!(
        card.verify_b(binding(CardInstanceV2::Required, 0x33)),
        Err(CardMockErrorV2::CardBindingMismatch)
    );
}

#[test]
fn card_mock_absence_precedes_public_binding_state() {
    let mut card = MockCardSlot::new(CardPresence::Absent);
    let required = binding(CardInstanceV2::Required, 0x44);
    assert_eq!(card.provision_b(required), Err(CardMockErrorV2::CardAbsent));
    assert_eq!(card.verify_b(required), Err(CardMockErrorV2::CardAbsent));
}

#[test]
fn normal_card_factor_is_bounded_move_only_and_clears_caller_secrets() {
    let mut oversized = [0x30; 73];
    assert!(matches!(
        NormalCardBSignatureV2::try_new(0, &mut oversized),
        Err(NormalCardMockErrorV2::SignatureTooLong)
    ));
    assert_eq!(oversized, [0; 73]);

    let mut der = [0x31; 71];
    let signature = NormalCardBSignatureV2::try_new(7, &mut der).expect("bounded DER owner");
    assert_eq!(der, [0; 71]);
    assert_eq!(signature.input_index(), 7);
    assert_eq!(signature.der_signature(), &[0x31; 71]);

    let descriptors = [[b'd'; 306], [b'c'; 306]];
    let wallet_id = [0x42; 32];
    let account_xpub = [b'x'; 111];
    let mut a2 = [0xa2; 32];
    let factor = NormalCardBDataV2::try_new(
        descriptors,
        wallet_id,
        account_xpub,
        &mut a2,
        vec![signature],
    )
    .expect("bounded card factor");
    assert_eq!(a2, [0; 32]);
    assert_eq!(factor.descriptors(), &descriptors);
    assert_eq!(factor.wallet_id(), wallet_id);
    assert_eq!(factor.account_xpub(), &account_xpub);
    assert_eq!(factor.signatures().len(), 1);
}
