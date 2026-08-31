#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_decoy::{
    ApplyOutcome, Calculator, CalculatorPhase, CalculatorRejection, DecoyKey, ALL_DECOY_KEYS,
    DISPLAY_CAPACITY, MAX_DIGIT_GLYPHS,
};

const MAX_PRESENTED_BYTES: usize = 2_048;
const MODEL_MAX_SCALE: u8 = 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModelValue {
    coefficient: i128,
    scale: u8,
}

impl ModelValue {
    const ZERO: Self = Self {
        coefficient: 0,
        scale: 0,
    };

    fn reduced(mut self) -> Self {
        if self.coefficient == 0 {
            return Self::ZERO;
        }
        while self.scale > 0 && self.coefficient % 10 == 0 {
            self.coefficient /= 10;
            self.scale -= 1;
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModelEntry {
    bytes: [u8; MAX_DIGIT_GLYPHS + 1],
    len: u8,
    digits: u8,
    decimal: bool,
}

impl ModelEntry {
    const fn zero() -> Self {
        let mut bytes = [0; MAX_DIGIT_GLYPHS + 1];
        bytes[0] = b'0';
        Self {
            bytes,
            len: 1,
            digits: 1,
            decimal: false,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn digit(&mut self, digit: u8) -> Result<(), CalculatorRejection> {
        if !self.decimal && self.len == 1 && self.bytes[0] == b'0' {
            if digit != b'0' {
                self.bytes[0] = digit;
            }
            return Ok(());
        }
        if usize::from(self.digits) == MAX_DIGIT_GLYPHS {
            return Err(CalculatorRejection::DigitLimitReached);
        }
        self.bytes[usize::from(self.len)] = digit;
        self.len += 1;
        self.digits += 1;
        Ok(())
    }

    fn decimal(&mut self) -> Result<(), CalculatorRejection> {
        if self.decimal {
            return Err(CalculatorRejection::DecimalAlreadyPresent);
        }
        self.bytes[usize::from(self.len)] = b'.';
        self.len += 1;
        self.decimal = true;
        Ok(())
    }

    fn value(&self) -> Option<ModelValue> {
        let mut coefficient = 0i128;
        let mut scale = 0u8;
        let mut fractional = false;
        for byte in self.bytes() {
            if *byte == b'.' {
                fractional = true;
            } else {
                coefficient = coefficient
                    .checked_mul(10)?
                    .checked_add(i128::from(*byte - b'0'))?;
                if fractional {
                    scale = scale.checked_add(1)?;
                }
            }
        }
        Some(ModelValue { coefficient, scale }.reduced())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelFault {
    Overflow,
    DivideByZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Model {
    phase: CalculatorPhase,
    display: [u8; DISPLAY_CAPACITY],
    display_len: u8,
    entry: ModelEntry,
    left: ModelValue,
    pending: Option<ModelOperator>,
    result: ModelValue,
}

impl Model {
    const fn new() -> Self {
        let mut display = [0; DISPLAY_CAPACITY];
        display[0] = b'0';
        Self {
            phase: CalculatorPhase::Entry,
            display,
            display_len: 1,
            entry: ModelEntry::zero(),
            left: ModelValue::ZERO,
            pending: None,
            result: ModelValue::ZERO,
        }
    }

    fn display(&self) -> &[u8] {
        &self.display[..usize::from(self.display_len)]
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn set_display(&mut self, value: &[u8]) {
        assert!(value.len() <= DISPLAY_CAPACITY);
        self.display.fill(0);
        self.display[..value.len()].copy_from_slice(value);
        self.display_len = value.len() as u8;
    }

    fn show_value(&mut self, value: ModelValue) {
        if let Some((bytes, len)) = model_render(value) {
            self.display = bytes;
            self.display_len = len;
        } else {
            self.set_display(b"OVERFLOW");
        }
    }

    fn finish(&mut self, value: ModelValue) -> ApplyOutcome {
        self.result = value;
        self.pending = None;
        self.phase = CalculatorPhase::Result;
        self.show_value(value);
        ApplyOutcome::Applied
    }

    fn fault(&mut self, fault: ModelFault) -> ApplyOutcome {
        self.pending = None;
        match fault {
            ModelFault::Overflow => {
                self.phase = CalculatorPhase::Overflow;
                self.set_display(b"OVERFLOW");
            }
            ModelFault::DivideByZero => {
                self.phase = CalculatorPhase::DivideByZero;
                self.set_display(b"DIVIDE BY 0");
            }
        }
        ApplyOutcome::Applied
    }

    fn apply(&mut self, key: DecoyKey) -> ApplyOutcome {
        if key == DecoyKey::CancelBack {
            self.clear();
            return ApplyOutcome::Applied;
        }
        if key == DecoyKey::CeDelete {
            return self.apply_ce();
        }
        if matches!(
            self.phase,
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero
        ) {
            return ApplyOutcome::Rejected(CalculatorRejection::FaultLatched);
        }
        if let Some(digit) = model_digit(key) {
            return self.apply_digit(digit);
        }
        if key == DecoyKey::Decimal {
            return self.apply_decimal();
        }
        if let Some(operator) = model_operator(key) {
            return self.apply_operator(operator);
        }
        match key {
            DecoyKey::Percent => self.apply_percent(),
            DecoyKey::EqualsConfirmEnter => self.apply_equals(),
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
            | DecoyKey::Divide
            | DecoyKey::CeDelete
            | DecoyKey::CancelBack => unreachable!("handled before the closed-key match"),
        }
    }

    fn begin_right_entry(&mut self) {
        if self.phase == CalculatorPhase::Result {
            self.clear();
        } else if self.phase == CalculatorPhase::AwaitingRight {
            self.entry = ModelEntry::zero();
            self.phase = CalculatorPhase::RightEntry;
        }
    }

    fn apply_digit(&mut self, digit: u8) -> ApplyOutcome {
        self.begin_right_entry();
        match self.entry.digit(digit) {
            Ok(()) => {
                let entry = self.entry;
                self.set_display(entry.bytes());
                ApplyOutcome::Applied
            }
            Err(error) => ApplyOutcome::Rejected(error),
        }
    }

    fn apply_decimal(&mut self) -> ApplyOutcome {
        self.begin_right_entry();
        match self.entry.decimal() {
            Ok(()) => {
                let entry = self.entry;
                self.set_display(entry.bytes());
                ApplyOutcome::Applied
            }
            Err(error) => ApplyOutcome::Rejected(error),
        }
    }

    fn apply_operator(&mut self, next: ModelOperator) -> ApplyOutcome {
        match self.phase {
            CalculatorPhase::Entry => {
                let Some(value) = self.entry.value() else {
                    return self.fault(ModelFault::Overflow);
                };
                self.left = value;
                self.pending = Some(next);
                self.phase = CalculatorPhase::AwaitingRight;
                self.show_value(value);
                ApplyOutcome::Applied
            }
            CalculatorPhase::AwaitingRight => {
                self.pending = Some(next);
                ApplyOutcome::Applied
            }
            CalculatorPhase::RightEntry => {
                let Some(right) = self.entry.value() else {
                    return self.fault(ModelFault::Overflow);
                };
                let Some(current) = self.pending else {
                    return self.fault(ModelFault::Overflow);
                };
                match model_evaluate(self.left, current, right) {
                    Ok(value) => {
                        self.left = value;
                        self.pending = Some(next);
                        self.phase = CalculatorPhase::AwaitingRight;
                        self.show_value(value);
                        ApplyOutcome::Applied
                    }
                    Err(fault) => self.fault(fault),
                }
            }
            CalculatorPhase::Result => {
                self.left = self.result;
                self.pending = Some(next);
                self.phase = CalculatorPhase::AwaitingRight;
                ApplyOutcome::Applied
            }
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => {
                ApplyOutcome::Rejected(CalculatorRejection::FaultLatched)
            }
        }
    }

    fn apply_percent(&mut self) -> ApplyOutcome {
        match self.phase {
            CalculatorPhase::Entry => {
                let Some(value) = self.entry.value() else {
                    return self.fault(ModelFault::Overflow);
                };
                match model_percent(value) {
                    Ok(value) => self.finish(value),
                    Err(fault) => self.fault(fault),
                }
            }
            CalculatorPhase::AwaitingRight => {
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
            }
            CalculatorPhase::RightEntry => {
                let Some(right) = self.entry.value() else {
                    return self.fault(ModelFault::Overflow);
                };
                let Some(operator) = self.pending else {
                    return self.fault(ModelFault::Overflow);
                };
                match model_percent(right)
                    .and_then(|percent| model_evaluate(self.left, operator, percent))
                {
                    Ok(value) => self.finish(value),
                    Err(fault) => self.fault(fault),
                }
            }
            CalculatorPhase::Result => match model_percent(self.result) {
                Ok(value) => self.finish(value),
                Err(fault) => self.fault(fault),
            },
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => {
                ApplyOutcome::Rejected(CalculatorRejection::FaultLatched)
            }
        }
    }

    fn apply_equals(&mut self) -> ApplyOutcome {
        match self.phase {
            CalculatorPhase::Entry => {
                let Some(value) = self.entry.value() else {
                    return self.fault(ModelFault::Overflow);
                };
                self.finish(value)
            }
            CalculatorPhase::AwaitingRight => {
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
            }
            CalculatorPhase::RightEntry => {
                let Some(right) = self.entry.value() else {
                    return self.fault(ModelFault::Overflow);
                };
                let Some(operator) = self.pending else {
                    return self.fault(ModelFault::Overflow);
                };
                match model_evaluate(self.left, operator, right) {
                    Ok(value) => self.finish(value),
                    Err(fault) => self.fault(fault),
                }
            }
            CalculatorPhase::Result => {
                ApplyOutcome::Rejected(CalculatorRejection::ResultAlreadyFinal)
            }
            CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => {
                ApplyOutcome::Rejected(CalculatorRejection::FaultLatched)
            }
        }
    }

    fn apply_ce(&mut self) -> ApplyOutcome {
        match self.phase {
            CalculatorPhase::Entry => {
                self.entry = ModelEntry::zero();
                self.set_display(b"0");
                ApplyOutcome::Applied
            }
            CalculatorPhase::AwaitingRight => {
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
            }
            CalculatorPhase::RightEntry => {
                self.entry = ModelEntry::zero();
                self.phase = CalculatorPhase::AwaitingRight;
                self.show_value(self.left);
                ApplyOutcome::Applied
            }
            CalculatorPhase::Result | CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => {
                self.clear();
                ApplyOutcome::Applied
            }
        }
    }
}

fn model_digit(key: DecoyKey) -> Option<u8> {
    match key {
        DecoyKey::Zero => Some(b'0'),
        DecoyKey::One => Some(b'1'),
        DecoyKey::TwoDown => Some(b'2'),
        DecoyKey::Three => Some(b'3'),
        DecoyKey::FourLeft => Some(b'4'),
        DecoyKey::Five => Some(b'5'),
        DecoyKey::SixRight => Some(b'6'),
        DecoyKey::Seven => Some(b'7'),
        DecoyKey::EightUp => Some(b'8'),
        DecoyKey::Nine => Some(b'9'),
        DecoyKey::Decimal
        | DecoyKey::Plus
        | DecoyKey::Minus
        | DecoyKey::Multiply
        | DecoyKey::Divide
        | DecoyKey::Percent
        | DecoyKey::CeDelete
        | DecoyKey::CancelBack
        | DecoyKey::EqualsConfirmEnter => None,
    }
}

fn model_operator(key: DecoyKey) -> Option<ModelOperator> {
    match key {
        DecoyKey::Plus => Some(ModelOperator::Add),
        DecoyKey::Minus => Some(ModelOperator::Subtract),
        DecoyKey::Multiply => Some(ModelOperator::Multiply),
        DecoyKey::Divide => Some(ModelOperator::Divide),
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
        | DecoyKey::Percent
        | DecoyKey::CeDelete
        | DecoyKey::CancelBack
        | DecoyKey::EqualsConfirmEnter => None,
    }
}

fn model_power(power: u8) -> Result<i128, ModelFault> {
    let mut result = 1i128;
    for _ in 0..power {
        result = result.checked_mul(10).ok_or(ModelFault::Overflow)?;
    }
    Ok(result)
}

fn model_digits(mut value: i128) -> usize {
    if value == 0 {
        return 1;
    }
    let mut count = 0usize;
    while value != 0 {
        count += 1;
        value /= 10;
    }
    count
}

fn model_glyphs(value: ModelValue) -> Option<usize> {
    let digits = model_digits(value.coefficient.checked_abs()?);
    Some(if usize::from(value.scale) >= digits {
        1 + usize::from(value.scale)
    } else {
        digits
    })
}

fn model_quantize(numerator: i128, denominator: i128) -> Result<ModelValue, ModelFault> {
    if denominator <= 0 {
        return Err(ModelFault::Overflow);
    }
    for scale in (0..=MODEL_MAX_SCALE).rev() {
        let power = model_power(scale)?;
        let Some(scaled) = numerator.checked_mul(power) else {
            continue;
        };
        let quotient = scaled / denominator;
        let remainder = scaled % denominator;
        let Some(double_remainder) = remainder.abs().checked_mul(2) else {
            continue;
        };
        let rounded = if double_remainder >= denominator {
            quotient.checked_add(if scaled < 0 { -1 } else { 1 })
        } else {
            Some(quotient)
        };
        let Some(coefficient) = rounded else {
            continue;
        };
        let candidate = ModelValue { coefficient, scale }.reduced();
        if model_glyphs(candidate).is_some_and(|glyphs| glyphs <= MAX_DIGIT_GLYPHS) {
            return Ok(candidate);
        }
    }
    Err(ModelFault::Overflow)
}

fn model_evaluate(
    left: ModelValue,
    operator: ModelOperator,
    right: ModelValue,
) -> Result<ModelValue, ModelFault> {
    match operator {
        ModelOperator::Add | ModelOperator::Subtract => {
            let scale = left.scale.max(right.scale);
            let left_scaled = left
                .coefficient
                .checked_mul(model_power(scale - left.scale)?)
                .ok_or(ModelFault::Overflow)?;
            let right_scaled = right
                .coefficient
                .checked_mul(model_power(scale - right.scale)?)
                .ok_or(ModelFault::Overflow)?;
            let numerator = if operator == ModelOperator::Add {
                left_scaled.checked_add(right_scaled)
            } else {
                left_scaled.checked_sub(right_scaled)
            }
            .ok_or(ModelFault::Overflow)?;
            model_quantize(numerator, model_power(scale)?)
        }
        ModelOperator::Multiply => {
            let numerator = left
                .coefficient
                .checked_mul(right.coefficient)
                .ok_or(ModelFault::Overflow)?;
            let scale = left
                .scale
                .checked_add(right.scale)
                .ok_or(ModelFault::Overflow)?;
            model_quantize(numerator, model_power(scale)?)
        }
        ModelOperator::Divide => {
            if right.coefficient == 0 {
                return Err(ModelFault::DivideByZero);
            }
            let numerator = left
                .coefficient
                .checked_mul(model_power(right.scale)?)
                .ok_or(ModelFault::Overflow)?;
            let denominator = right
                .coefficient
                .checked_mul(model_power(left.scale)?)
                .ok_or(ModelFault::Overflow)?;
            if denominator < 0 {
                model_quantize(
                    numerator.checked_neg().ok_or(ModelFault::Overflow)?,
                    denominator.checked_neg().ok_or(ModelFault::Overflow)?,
                )
            } else {
                model_quantize(numerator, denominator)
            }
        }
    }
}

fn model_percent(value: ModelValue) -> Result<ModelValue, ModelFault> {
    let scale = value.scale.checked_add(2).ok_or(ModelFault::Overflow)?;
    model_quantize(value.coefficient, model_power(scale)?)
}

fn model_render(value: ModelValue) -> Option<([u8; DISPLAY_CAPACITY], u8)> {
    let value = value.reduced();
    if model_glyphs(value)? > MAX_DIGIT_GLYPHS {
        return None;
    }
    let negative = value.coefficient < 0;
    let mut magnitude = value.coefficient.checked_abs()?;
    let mut reverse = [0u8; MAX_DIGIT_GLYPHS];
    let mut digits = 0usize;
    loop {
        reverse[digits] = b'0' + u8::try_from(magnitude % 10).ok()?;
        digits += 1;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }

    let mut display = [0u8; DISPLAY_CAPACITY];
    let mut len = 0usize;
    if negative {
        display[len] = b'-';
        len += 1;
    }
    let scale = usize::from(value.scale);
    if scale == 0 {
        for index in (0..digits).rev() {
            display[len] = reverse[index];
            len += 1;
        }
    } else if digits <= scale {
        display[len] = b'0';
        display[len + 1] = b'.';
        len += 2;
        for _ in 0..(scale - digits) {
            display[len] = b'0';
            len += 1;
        }
        for index in (0..digits).rev() {
            display[len] = reverse[index];
            len += 1;
        }
    } else {
        for index in (0..digits).rev() {
            if index + 1 == scale {
                display[len] = b'.';
                len += 1;
            }
            display[len] = reverse[index];
            len += 1;
        }
    }
    Some((display, len as u8))
}

fn rejection_name(error: CalculatorRejection) -> &'static str {
    match error {
        CalculatorRejection::DigitLimitReached => "DigitLimitReached",
        CalculatorRejection::DecimalAlreadyPresent => "DecimalAlreadyPresent",
        CalculatorRejection::OperandMissing => "OperandMissing",
        CalculatorRejection::ResultAlreadyFinal => "ResultAlreadyFinal",
        CalculatorRejection::FaultLatched => "FaultLatched",
    }
}

fn assert_display(phase: CalculatorPhase, bytes: &[u8]) {
    match phase {
        CalculatorPhase::Overflow => {
            assert_eq!(bytes, b"OVERFLOW");
            return;
        }
        CalculatorPhase::DivideByZero => {
            assert_eq!(bytes, b"DIVIDE BY 0");
            return;
        }
        CalculatorPhase::Entry
        | CalculatorPhase::AwaitingRight
        | CalculatorPhase::RightEntry
        | CalculatorPhase::Result => {}
    }

    let mut digits = 0usize;
    let mut decimals = 0usize;
    for (position, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'0'..=b'9' => digits += 1,
            b'.' => decimals += 1,
            b'-' => assert_eq!(position, 0),
            _ => panic!("calculator display contains a non-canonical byte"),
        }
    }
    assert!((1..=MAX_DIGIT_GLYPHS).contains(&digits));
    assert!(decimals <= 1);
    assert_ne!(bytes, b"-0");
}

fn drive(data: &[u8]) {
    let mut calculator = Calculator::new();
    let mut model = Model::new();
    assert_eq!(calculator.phase(), model.phase);
    assert_eq!(calculator.display().as_bytes(), model.display());

    for selector in data.iter().copied() {
        let key = ALL_DECOY_KEYS[usize::from(selector) % ALL_DECOY_KEYS.len()];
        let before_phase = calculator.phase();
        let before_display = calculator.display();
        let before_model = model;
        let expected = model.apply(key);
        let actual = calculator.apply(key);

        assert_eq!(actual, expected);
        assert_eq!(calculator.phase(), model.phase);
        assert_eq!(calculator.display().as_bytes(), model.display());
        assert_display(calculator.phase(), calculator.display().as_bytes());

        if let ApplyOutcome::Rejected(error) = actual {
            assert_eq!(error.name(), rejection_name(error));
            assert_eq!(error.to_string(), rejection_name(error));
            assert_eq!(calculator.phase(), before_phase);
            assert_eq!(calculator.display(), before_display);
            assert_eq!(model, before_model);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(ALL_DECOY_KEYS.len(), 19);
    assert_eq!(MAX_DIGIT_GLYPHS, 12);
    assert_eq!(DISPLAY_CAPACITY, 14);
    let bounded = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    drive(bounded);
    drive(bounded);
});
