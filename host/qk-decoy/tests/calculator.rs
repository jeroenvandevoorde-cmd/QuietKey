use qk_decoy::{
    ApplyOutcome, Calculator, CalculatorPhase, CalculatorRejection, DecoyKey, ALL_DECOY_KEYS,
    DISPLAY_CAPACITY, MAX_DIGIT_GLYPHS,
};

fn press(calculator: &mut Calculator, key: DecoyKey) {
    assert_eq!(calculator.apply(key), ApplyOutcome::Applied);
}

fn text(calculator: &Calculator) -> Vec<u8> {
    calculator.display().as_bytes().to_vec()
}

fn enter(calculator: &mut Calculator, value: &[u8]) {
    for byte in value {
        let key = match byte {
            b'0' => DecoyKey::Zero,
            b'1' => DecoyKey::One,
            b'2' => DecoyKey::TwoDown,
            b'3' => DecoyKey::Three,
            b'4' => DecoyKey::FourLeft,
            b'5' => DecoyKey::Five,
            b'6' => DecoyKey::SixRight,
            b'7' => DecoyKey::Seven,
            b'8' => DecoyKey::EightUp,
            b'9' => DecoyKey::Nine,
            b'.' => DecoyKey::Decimal,
            _ => panic!("test input"),
        };
        press(calculator, key);
    }
}

#[test]
fn exact_public_constants_and_key_order_are_locked() {
    assert_eq!(MAX_DIGIT_GLYPHS, 12);
    assert_eq!(DISPLAY_CAPACITY, 14);
    assert_eq!(ALL_DECOY_KEYS.len(), 19);
    assert_eq!(
        ALL_DECOY_KEYS,
        [
            DecoyKey::Zero,
            DecoyKey::One,
            DecoyKey::TwoDown,
            DecoyKey::Three,
            DecoyKey::FourLeft,
            DecoyKey::Five,
            DecoyKey::SixRight,
            DecoyKey::Seven,
            DecoyKey::EightUp,
            DecoyKey::Nine,
            DecoyKey::Decimal,
            DecoyKey::Plus,
            DecoyKey::Minus,
            DecoyKey::Multiply,
            DecoyKey::Divide,
            DecoyKey::Percent,
            DecoyKey::CeDelete,
            DecoyKey::CancelBack,
            DecoyKey::EqualsConfirmEnter,
        ]
    );
}

#[test]
fn entry_canonicalizes_leading_zero_and_enforces_decimal_and_digit_caps() {
    let mut calculator = Calculator::new();
    assert_eq!(calculator.phase(), CalculatorPhase::Entry);
    assert_eq!(text(&calculator), b"0");
    press(&mut calculator, DecoyKey::Zero);
    press(&mut calculator, DecoyKey::Zero);
    assert_eq!(text(&calculator), b"0");
    enter(&mut calculator, b"123456789012");
    assert_eq!(text(&calculator), b"123456789012");
    assert_eq!(
        calculator.apply(DecoyKey::Three),
        ApplyOutcome::Rejected(CalculatorRejection::DigitLimitReached)
    );
    assert_eq!(text(&calculator), b"123456789012");

    press(&mut calculator, DecoyKey::CancelBack);
    press(&mut calculator, DecoyKey::Decimal);
    assert_eq!(text(&calculator), b"0.");
    assert_eq!(
        calculator.apply(DecoyKey::Decimal),
        ApplyOutcome::Rejected(CalculatorRejection::DecimalAlreadyPresent)
    );
    enter(&mut calculator, b"12345678901");
    assert_eq!(text(&calculator), b"0.12345678901");
    assert_eq!(
        calculator.apply(DecoyKey::TwoDown),
        ApplyOutcome::Rejected(CalculatorRejection::DigitLimitReached)
    );
}

#[test]
fn four_functions_are_immediate_left_to_right_and_minus_is_binary() {
    let mut calculator = Calculator::new();
    enter(&mut calculator, b"2");
    press(&mut calculator, DecoyKey::Plus);
    enter(&mut calculator, b"3");
    press(&mut calculator, DecoyKey::Multiply);
    assert_eq!(calculator.phase(), CalculatorPhase::AwaitingRight);
    assert_eq!(text(&calculator), b"5");
    enter(&mut calculator, b"4");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"20");

    press(&mut calculator, DecoyKey::CancelBack);
    enter(&mut calculator, b"1");
    press(&mut calculator, DecoyKey::Minus);
    enter(&mut calculator, b"2");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"-1");
    press(&mut calculator, DecoyKey::Multiply);
    enter(&mut calculator, b"3");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"-3");
}

#[test]
fn pending_operator_replacement_and_missing_operand_are_exact() {
    let mut calculator = Calculator::new();
    enter(&mut calculator, b"8");
    press(&mut calculator, DecoyKey::Plus);
    press(&mut calculator, DecoyKey::Divide);
    assert_eq!(calculator.phase(), CalculatorPhase::AwaitingRight);
    assert_eq!(
        calculator.apply(DecoyKey::EqualsConfirmEnter),
        ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
    );
    assert_eq!(
        calculator.apply(DecoyKey::Percent),
        ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
    );
    enter(&mut calculator, b"2");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"4");
    assert_eq!(
        calculator.apply(DecoyKey::EqualsConfirmEnter),
        ApplyOutcome::Rejected(CalculatorRejection::ResultAlreadyFinal)
    );
    assert_eq!(text(&calculator), b"4");
}

#[test]
fn percent_is_context_free_division_by_one_hundred() {
    let mut calculator = Calculator::new();
    enter(&mut calculator, b"50");
    press(&mut calculator, DecoyKey::Percent);
    assert_eq!(text(&calculator), b"0.5");
    press(&mut calculator, DecoyKey::Percent);
    assert_eq!(text(&calculator), b"0.005");

    press(&mut calculator, DecoyKey::CancelBack);
    enter(&mut calculator, b"200");
    press(&mut calculator, DecoyKey::Plus);
    enter(&mut calculator, b"10");
    press(&mut calculator, DecoyKey::Percent);
    assert_eq!(calculator.phase(), CalculatorPhase::Result);
    assert_eq!(text(&calculator), b"200.1");
}

#[test]
fn division_rounds_to_maximal_fixed_precision_with_ties_away_from_zero() {
    let mut calculator = Calculator::new();
    enter(&mut calculator, b"1");
    press(&mut calculator, DecoyKey::Divide);
    enter(&mut calculator, b"3");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"0.33333333333");

    press(&mut calculator, DecoyKey::CancelBack);
    enter(&mut calculator, b"2");
    press(&mut calculator, DecoyKey::Divide);
    enter(&mut calculator, b"3");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"0.66666666667");

    // 0.000000000005 has no 12-digit fixed rendering at scale 12; scale 11
    // is the exact positive half and rounds away from zero.
    press(&mut calculator, DecoyKey::CancelBack);
    enter(&mut calculator, b"0.00000000001");
    press(&mut calculator, DecoyKey::Divide);
    enter(&mut calculator, b"2");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"0.00000000001");

    press(&mut calculator, DecoyKey::CancelBack);
    press(&mut calculator, DecoyKey::Minus);
    enter(&mut calculator, b"0.00000000001");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    press(&mut calculator, DecoyKey::Divide);
    enter(&mut calculator, b"2");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"-0.00000000001");
}

#[test]
fn overflow_and_divide_by_zero_are_exact_latched_displays() {
    let mut calculator = Calculator::new();
    enter(&mut calculator, b"999999999999");
    press(&mut calculator, DecoyKey::Plus);
    enter(&mut calculator, b"1");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(calculator.phase(), CalculatorPhase::Overflow);
    assert_eq!(text(&calculator), b"OVERFLOW");
    for key in ALL_DECOY_KEYS {
        if matches!(key, DecoyKey::CeDelete | DecoyKey::CancelBack) {
            continue;
        }
        assert_eq!(
            calculator.apply(key),
            ApplyOutcome::Rejected(CalculatorRejection::FaultLatched)
        );
        assert_eq!(text(&calculator), b"OVERFLOW");
    }
    press(&mut calculator, DecoyKey::CeDelete);
    assert_eq!(calculator.phase(), CalculatorPhase::Entry);
    assert_eq!(text(&calculator), b"0");

    enter(&mut calculator, b"1");
    press(&mut calculator, DecoyKey::Divide);
    enter(&mut calculator, b"0");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(calculator.phase(), CalculatorPhase::DivideByZero);
    assert_eq!(text(&calculator), b"DIVIDE BY 0");
    assert_eq!(
        calculator.apply(DecoyKey::One),
        ApplyOutcome::Rejected(CalculatorRejection::FaultLatched)
    );
    press(&mut calculator, DecoyKey::CancelBack);
    assert_eq!(text(&calculator), b"0");
}

#[test]
fn ce_and_red_c_have_distinct_complete_semantics() {
    let mut calculator = Calculator::new();
    enter(&mut calculator, b"12");
    press(&mut calculator, DecoyKey::Plus);
    enter(&mut calculator, b"34");
    press(&mut calculator, DecoyKey::CeDelete);
    assert_eq!(calculator.phase(), CalculatorPhase::AwaitingRight);
    assert_eq!(text(&calculator), b"12");
    enter(&mut calculator, b"5");
    press(&mut calculator, DecoyKey::EqualsConfirmEnter);
    assert_eq!(text(&calculator), b"17");
    press(&mut calculator, DecoyKey::CeDelete);
    assert_eq!(text(&calculator), b"0");

    enter(&mut calculator, b"9");
    press(&mut calculator, DecoyKey::Multiply);
    enter(&mut calculator, b"8");
    press(&mut calculator, DecoyKey::CancelBack);
    assert_eq!(calculator.phase(), CalculatorPhase::Entry);
    assert_eq!(text(&calculator), b"0");
}

#[test]
fn rejection_names_are_exact_and_non_hostile() {
    let cases = [
        (CalculatorRejection::DigitLimitReached, "DigitLimitReached"),
        (
            CalculatorRejection::DecimalAlreadyPresent,
            "DecimalAlreadyPresent",
        ),
        (CalculatorRejection::OperandMissing, "OperandMissing"),
        (
            CalculatorRejection::ResultAlreadyFinal,
            "ResultAlreadyFinal",
        ),
        (CalculatorRejection::FaultLatched, "FaultLatched"),
    ];
    for (error, expected) in cases {
        assert_eq!(error.name(), expected);
        assert_eq!(error.to_string(), expected);
    }
}
