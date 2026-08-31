use qk_decoy::{
    ApplyOutcome, Calculator, CalculatorPhase, CalculatorRejection, DecoyKey, ALL_DECOY_KEYS,
};

fn applied(calculator: &mut Calculator, key: DecoyKey) {
    assert_eq!(calculator.apply(key), ApplyOutcome::Applied);
}

fn entry() -> Calculator {
    Calculator::new()
}

fn awaiting_right() -> Calculator {
    let mut calculator = Calculator::new();
    applied(&mut calculator, DecoyKey::One);
    applied(&mut calculator, DecoyKey::Plus);
    calculator
}

fn right_entry() -> Calculator {
    let mut calculator = awaiting_right();
    applied(&mut calculator, DecoyKey::TwoDown);
    calculator
}

fn result() -> Calculator {
    let mut calculator = Calculator::new();
    applied(&mut calculator, DecoyKey::One);
    applied(&mut calculator, DecoyKey::EqualsConfirmEnter);
    calculator
}

fn overflow() -> Calculator {
    let mut calculator = Calculator::new();
    for key in [
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Nine,
        DecoyKey::Plus,
        DecoyKey::One,
        DecoyKey::EqualsConfirmEnter,
    ] {
        applied(&mut calculator, key);
    }
    assert_eq!(calculator.phase(), CalculatorPhase::Overflow);
    calculator
}

fn divide_by_zero() -> Calculator {
    let mut calculator = Calculator::new();
    for key in [
        DecoyKey::One,
        DecoyKey::Divide,
        DecoyKey::Zero,
        DecoyKey::EqualsConfirmEnter,
    ] {
        applied(&mut calculator, key);
    }
    assert_eq!(calculator.phase(), CalculatorPhase::DivideByZero);
    calculator
}

fn is_digit(key: DecoyKey) -> bool {
    matches!(
        key,
        DecoyKey::Zero
            | DecoyKey::One
            | DecoyKey::TwoDown
            | DecoyKey::Three
            | DecoyKey::FourLeft
            | DecoyKey::Five
            | DecoyKey::SixRight
            | DecoyKey::Seven
            | DecoyKey::EightUp
            | DecoyKey::Nine
    )
}

fn is_operator(key: DecoyKey) -> bool {
    matches!(
        key,
        DecoyKey::Plus | DecoyKey::Minus | DecoyKey::Multiply | DecoyKey::Divide
    )
}

fn expected(phase: CalculatorPhase, key: DecoyKey) -> (ApplyOutcome, CalculatorPhase) {
    if matches!(
        phase,
        CalculatorPhase::Overflow | CalculatorPhase::DivideByZero
    ) {
        return if matches!(key, DecoyKey::CeDelete | DecoyKey::CancelBack) {
            (ApplyOutcome::Applied, CalculatorPhase::Entry)
        } else {
            (
                ApplyOutcome::Rejected(CalculatorRejection::FaultLatched),
                phase,
            )
        };
    }
    if is_digit(key) {
        return (
            ApplyOutcome::Applied,
            match phase {
                CalculatorPhase::AwaitingRight | CalculatorPhase::RightEntry => {
                    CalculatorPhase::RightEntry
                }
                CalculatorPhase::Entry | CalculatorPhase::Result => CalculatorPhase::Entry,
                CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => unreachable!(),
            },
        );
    }
    if key == DecoyKey::Decimal {
        return (
            ApplyOutcome::Applied,
            match phase {
                CalculatorPhase::AwaitingRight | CalculatorPhase::RightEntry => {
                    CalculatorPhase::RightEntry
                }
                CalculatorPhase::Entry | CalculatorPhase::Result => CalculatorPhase::Entry,
                CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => unreachable!(),
            },
        );
    }
    if is_operator(key) {
        return (ApplyOutcome::Applied, CalculatorPhase::AwaitingRight);
    }
    match key {
        DecoyKey::Percent => match phase {
            CalculatorPhase::AwaitingRight => (
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing),
                CalculatorPhase::AwaitingRight,
            ),
            CalculatorPhase::Entry | CalculatorPhase::RightEntry | CalculatorPhase::Result => {
                (ApplyOutcome::Applied, CalculatorPhase::Result)
            }
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => unreachable!(),
        },
        DecoyKey::CeDelete => match phase {
            CalculatorPhase::AwaitingRight => (
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing),
                CalculatorPhase::AwaitingRight,
            ),
            CalculatorPhase::RightEntry => (ApplyOutcome::Applied, CalculatorPhase::AwaitingRight),
            CalculatorPhase::Entry | CalculatorPhase::Result => {
                (ApplyOutcome::Applied, CalculatorPhase::Entry)
            }
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => unreachable!(),
        },
        DecoyKey::CancelBack => (ApplyOutcome::Applied, CalculatorPhase::Entry),
        DecoyKey::EqualsConfirmEnter => match phase {
            CalculatorPhase::AwaitingRight => (
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing),
                CalculatorPhase::AwaitingRight,
            ),
            CalculatorPhase::Result => (
                ApplyOutcome::Rejected(CalculatorRejection::ResultAlreadyFinal),
                CalculatorPhase::Result,
            ),
            CalculatorPhase::Entry | CalculatorPhase::RightEntry => {
                (ApplyOutcome::Applied, CalculatorPhase::Result)
            }
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => unreachable!(),
        },
        DecoyKey::Zero
        | DecoyKey::One
        | DecoyKey::TwoDown
        | DecoyKey::Three
        | DecoyKey::FourLeft
        | DecoyKey::Five
        | DecoyKey::SixRight
        | DecoyKey::Seven
        | DecoyKey::EightUp
        | DecoyKey::Nine
        | DecoyKey::Decimal
        | DecoyKey::Plus
        | DecoyKey::Minus
        | DecoyKey::Multiply
        | DecoyKey::Divide => unreachable!(),
    }
}

#[test]
fn all_nineteen_keys_have_an_exact_effect_in_all_six_phases() {
    let phases: [(CalculatorPhase, fn() -> Calculator); 6] = [
        (CalculatorPhase::Entry, entry),
        (CalculatorPhase::AwaitingRight, awaiting_right),
        (CalculatorPhase::RightEntry, right_entry),
        (CalculatorPhase::Result, result),
        (CalculatorPhase::Overflow, overflow),
        (CalculatorPhase::DivideByZero, divide_by_zero),
    ];
    let mut cells = 0usize;
    for (phase, constructor) in phases {
        for key in ALL_DECOY_KEYS {
            let mut calculator = constructor();
            let expected = expected(phase, key);
            let actual = calculator.apply(key);
            assert_eq!(actual, expected.0, "outcome for {phase:?} + {key:?}");
            assert_eq!(
                calculator.phase(),
                expected.1,
                "phase for {phase:?} + {key:?}"
            );
            cells += 1;
        }
    }
    assert_eq!(cells, 6 * 19);
}

#[test]
fn repeated_complete_sequences_are_deterministic() {
    let keys = [
        DecoyKey::Nine,
        DecoyKey::Decimal,
        DecoyKey::Five,
        DecoyKey::Multiply,
        DecoyKey::TwoDown,
        DecoyKey::Minus,
        DecoyKey::One,
        DecoyKey::Percent,
        DecoyKey::Plus,
        DecoyKey::Three,
        DecoyKey::EqualsConfirmEnter,
    ];
    let mut first = Calculator::new();
    let mut second = Calculator::new();
    for key in keys {
        assert_eq!(first.apply(key), second.apply(key));
        assert_eq!(first.phase(), second.phase());
        assert_eq!(first.display(), second.display());
    }
}
