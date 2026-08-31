use core::fmt;

/// Maximum numeric glyphs in one normal calculator display.
pub const MAX_DIGIT_GLYPHS: usize = 12;
/// One sign, twelve digits, and one decimal point.
pub const DISPLAY_CAPACITY: usize = MAX_DIGIT_GLYPHS + 2;

const OVERFLOW_DISPLAY: &[u8] = b"OVERFLOW";
const DIVIDE_BY_ZERO_DISPLAY: &[u8] = b"DIVIDE BY 0";
const MAX_SCALE: u8 = 11;

/// Exact nineteen-key logical P0.1 vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecoyKey {
    Zero,
    One,
    TwoDown,
    Three,
    FourLeft,
    Five,
    SixRight,
    Seven,
    EightUp,
    Nine,
    Decimal,
    Plus,
    Minus,
    Multiply,
    Divide,
    Percent,
    CeDelete,
    CancelBack,
    EqualsConfirmEnter,
}

/// Exact P0.1 key order used by table tests and the ring-fenced target.
pub const ALL_DECOY_KEYS: [DecoyKey; 19] = [
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
];

/// Exact six-state public calculator phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalculatorPhase {
    Entry,
    AwaitingRight,
    RightEntry,
    Result,
    Overflow,
    DivideByZero,
}

/// Closed set of state-preserving calculator rejections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalculatorRejection {
    DigitLimitReached,
    DecimalAlreadyPresent,
    OperandMissing,
    ResultAlreadyFinal,
    FaultLatched,
}

impl CalculatorRejection {
    /// Stable non-hostile name for routing and exhaustive oracles.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DigitLimitReached => "DigitLimitReached",
            Self::DecimalAlreadyPresent => "DecimalAlreadyPresent",
            Self::OperandMissing => "OperandMissing",
            Self::ResultAlreadyFinal => "ResultAlreadyFinal",
            Self::FaultLatched => "FaultLatched",
        }
    }
}

impl fmt::Display for CalculatorRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for CalculatorRejection {}

/// Total result of one logical key application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Applied,
    Rejected(CalculatorRejection),
}

/// Fixed-capacity ASCII display value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayText {
    bytes: [u8; DISPLAY_CAPACITY],
    len: u8,
}

impl DisplayText {
    const fn zero() -> Self {
        let mut bytes = [0; DISPLAY_CAPACITY];
        bytes[0] = b'0';
        Self { bytes, len: 1 }
    }

    fn from_known_ascii(source: &[u8]) -> Self {
        debug_assert!(source.len() <= DISPLAY_CAPACITY);
        let mut display = Self {
            bytes: [0; DISPLAY_CAPACITY],
            len: source.len() as u8,
        };
        display.bytes[..source.len()].copy_from_slice(source);
        display
    }

    /// Exact displayed bytes, without padding or a terminator.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecimalValue {
    coefficient: i128,
    scale: u8,
}

impl DecimalValue {
    const ZERO: Self = Self {
        coefficient: 0,
        scale: 0,
    };

    fn normalized(mut self) -> Self {
        if self.coefficient == 0 {
            return Self::ZERO;
        }
        while self.scale != 0 && self.coefficient % 10 == 0 {
            self.coefficient /= 10;
            self.scale -= 1;
        }
        self
    }
}

#[derive(Clone, Copy)]
struct EntryBuffer {
    bytes: [u8; MAX_DIGIT_GLYPHS + 1],
    len: u8,
    digits: u8,
    decimal: bool,
}

impl EntryBuffer {
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

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn push_digit(&mut self, digit: u8) -> Result<(), CalculatorRejection> {
        debug_assert!(digit.is_ascii_digit());
        if !self.decimal && self.len == 1 && self.bytes[0] == b'0' {
            // Redundant leading zeroes canonicalize to the existing zero.
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

    fn push_decimal(&mut self) -> Result<(), CalculatorRejection> {
        if self.decimal {
            return Err(CalculatorRejection::DecimalAlreadyPresent);
        }
        self.bytes[usize::from(self.len)] = b'.';
        self.len += 1;
        self.decimal = true;
        Ok(())
    }

    fn value(self) -> Option<DecimalValue> {
        let mut coefficient = 0i128;
        let mut scale = 0u8;
        let mut after_decimal = false;
        for byte in self.as_bytes() {
            if *byte == b'.' {
                after_decimal = true;
                continue;
            }
            coefficient = coefficient
                .checked_mul(10)?
                .checked_add(i128::from(*byte - b'0'))?;
            if after_decimal {
                scale = scale.checked_add(1)?;
            }
        }
        Some(DecimalValue { coefficient, scale }.normalized())
    }
}

/// Total, fixed-memory QK-DEC-142 calculator state machine.
pub struct Calculator {
    phase: CalculatorPhase,
    display: DisplayText,
    entry: EntryBuffer,
    left: DecimalValue,
    pending: Option<BinaryOperator>,
    result: DecimalValue,
}

impl Default for Calculator {
    fn default() -> Self {
        Self::new()
    }
}

impl Calculator {
    /// Initial cleared calculator displaying exact ASCII `0`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: CalculatorPhase::Entry,
            display: DisplayText::zero(),
            entry: EntryBuffer::zero(),
            left: DecimalValue::ZERO,
            pending: None,
            result: DecimalValue::ZERO,
        }
    }

    /// Current exact public phase.
    #[must_use]
    pub const fn phase(&self) -> CalculatorPhase {
        self.phase
    }

    /// Current exact display bytes.
    #[must_use]
    pub const fn display(&self) -> DisplayText {
        self.display
    }

    /// Apply one P0.1 logical key. Every key in every phase is handled.
    pub fn apply(&mut self, key: DecoyKey) -> ApplyOutcome {
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

        match key {
            DecoyKey::Zero
            | DecoyKey::One
            | DecoyKey::TwoDown
            | DecoyKey::Three
            | DecoyKey::FourLeft
            | DecoyKey::Five
            | DecoyKey::SixRight
            | DecoyKey::Seven
            | DecoyKey::EightUp
            | DecoyKey::Nine => self.apply_digit(digit_byte(key)),
            DecoyKey::Decimal => self.apply_decimal(),
            DecoyKey::Plus | DecoyKey::Minus | DecoyKey::Multiply | DecoyKey::Divide => {
                self.apply_operator(operator(key))
            }
            DecoyKey::Percent => self.apply_percent(),
            DecoyKey::EqualsConfirmEnter => self.apply_equals(),
            DecoyKey::CeDelete => self.apply_ce(),
            DecoyKey::CancelBack => {
                self.clear();
                ApplyOutcome::Applied
            }
        }
    }

    fn apply_digit(&mut self, digit: u8) -> ApplyOutcome {
        if self.phase == CalculatorPhase::Result {
            self.clear();
        } else if self.phase == CalculatorPhase::AwaitingRight {
            self.entry = EntryBuffer::zero();
            self.phase = CalculatorPhase::RightEntry;
        }
        match self.entry.push_digit(digit) {
            Ok(()) => {
                self.display = DisplayText::from_known_ascii(self.entry.as_bytes());
                ApplyOutcome::Applied
            }
            Err(error) => ApplyOutcome::Rejected(error),
        }
    }

    fn apply_decimal(&mut self) -> ApplyOutcome {
        if self.phase == CalculatorPhase::Result {
            self.clear();
        } else if self.phase == CalculatorPhase::AwaitingRight {
            self.entry = EntryBuffer::zero();
            self.phase = CalculatorPhase::RightEntry;
        }
        match self.entry.push_decimal() {
            Ok(()) => {
                self.display = DisplayText::from_known_ascii(self.entry.as_bytes());
                ApplyOutcome::Applied
            }
            Err(error) => ApplyOutcome::Rejected(error),
        }
    }

    fn apply_operator(&mut self, next: BinaryOperator) -> ApplyOutcome {
        match self.phase {
            CalculatorPhase::Entry => {
                let Some(value) = self.entry.value() else {
                    return self.enter_overflow();
                };
                self.left = value;
                self.pending = Some(next);
                self.phase = CalculatorPhase::AwaitingRight;
                self.display_value(value);
                ApplyOutcome::Applied
            }
            CalculatorPhase::AwaitingRight => {
                self.pending = Some(next);
                ApplyOutcome::Applied
            }
            CalculatorPhase::RightEntry => {
                let Some(right) = self.entry.value() else {
                    return self.enter_overflow();
                };
                let Some(current) = self.pending else {
                    return self.enter_overflow();
                };
                match evaluate(self.left, current, right) {
                    Ok(value) => {
                        self.left = value;
                        self.pending = Some(next);
                        self.phase = CalculatorPhase::AwaitingRight;
                        self.display_value(value);
                        ApplyOutcome::Applied
                    }
                    Err(error) => self.enter_fault(error),
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
                    return self.enter_overflow();
                };
                match percent(value) {
                    Ok(value) => self.enter_result(value),
                    Err(error) => self.enter_fault(error),
                }
            }
            CalculatorPhase::AwaitingRight => {
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
            }
            CalculatorPhase::RightEntry => {
                let Some(right) = self.entry.value() else {
                    return self.enter_overflow();
                };
                let Some(current) = self.pending else {
                    return self.enter_overflow();
                };
                let result = percent(right).and_then(|value| evaluate(self.left, current, value));
                match result {
                    Ok(value) => self.enter_result(value),
                    Err(error) => self.enter_fault(error),
                }
            }
            CalculatorPhase::Result => match percent(self.result) {
                Ok(value) => self.enter_result(value),
                Err(error) => self.enter_fault(error),
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
                    return self.enter_overflow();
                };
                self.enter_result(value)
            }
            CalculatorPhase::AwaitingRight => {
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
            }
            CalculatorPhase::RightEntry => {
                let Some(right) = self.entry.value() else {
                    return self.enter_overflow();
                };
                let Some(current) = self.pending else {
                    return self.enter_overflow();
                };
                match evaluate(self.left, current, right) {
                    Ok(value) => self.enter_result(value),
                    Err(error) => self.enter_fault(error),
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
                self.entry = EntryBuffer::zero();
                self.display = DisplayText::zero();
                ApplyOutcome::Applied
            }
            CalculatorPhase::AwaitingRight => {
                ApplyOutcome::Rejected(CalculatorRejection::OperandMissing)
            }
            CalculatorPhase::RightEntry => {
                self.entry = EntryBuffer::zero();
                self.phase = CalculatorPhase::AwaitingRight;
                self.display_value(self.left);
                ApplyOutcome::Applied
            }
            CalculatorPhase::Result | CalculatorPhase::Overflow | CalculatorPhase::DivideByZero => {
                self.clear();
                ApplyOutcome::Applied
            }
        }
    }

    fn enter_result(&mut self, value: DecimalValue) -> ApplyOutcome {
        self.result = value;
        self.pending = None;
        self.phase = CalculatorPhase::Result;
        self.display_value(value);
        ApplyOutcome::Applied
    }

    fn enter_fault(&mut self, error: ArithmeticError) -> ApplyOutcome {
        match error {
            ArithmeticError::Overflow => self.enter_overflow(),
            ArithmeticError::DivideByZero => {
                self.phase = CalculatorPhase::DivideByZero;
                self.pending = None;
                self.display = DisplayText::from_known_ascii(DIVIDE_BY_ZERO_DISPLAY);
                ApplyOutcome::Applied
            }
        }
    }

    fn enter_overflow(&mut self) -> ApplyOutcome {
        self.phase = CalculatorPhase::Overflow;
        self.pending = None;
        self.display = DisplayText::from_known_ascii(OVERFLOW_DISPLAY);
        ApplyOutcome::Applied
    }

    fn display_value(&mut self, value: DecimalValue) {
        self.display =
            render(value).unwrap_or_else(|| DisplayText::from_known_ascii(OVERFLOW_DISPLAY));
    }

    fn clear(&mut self) {
        *self = Self::new();
    }
}

#[derive(Clone, Copy)]
enum ArithmeticError {
    Overflow,
    DivideByZero,
}

fn evaluate(
    left: DecimalValue,
    operator: BinaryOperator,
    right: DecimalValue,
) -> Result<DecimalValue, ArithmeticError> {
    match operator {
        BinaryOperator::Add | BinaryOperator::Subtract => {
            let scale = left.scale.max(right.scale);
            let left_factor = power_of_ten(scale - left.scale)?;
            let right_factor = power_of_ten(scale - right.scale)?;
            let left_coefficient = left
                .coefficient
                .checked_mul(left_factor)
                .ok_or(ArithmeticError::Overflow)?;
            let right_coefficient = right
                .coefficient
                .checked_mul(right_factor)
                .ok_or(ArithmeticError::Overflow)?;
            let numerator = if operator == BinaryOperator::Add {
                left_coefficient.checked_add(right_coefficient)
            } else {
                left_coefficient.checked_sub(right_coefficient)
            }
            .ok_or(ArithmeticError::Overflow)?;
            quantize(numerator, power_of_ten(scale)?)
        }
        BinaryOperator::Multiply => {
            let numerator = left
                .coefficient
                .checked_mul(right.coefficient)
                .ok_or(ArithmeticError::Overflow)?;
            let scale = left
                .scale
                .checked_add(right.scale)
                .ok_or(ArithmeticError::Overflow)?;
            quantize(numerator, power_of_ten(scale)?)
        }
        BinaryOperator::Divide => {
            if right.coefficient == 0 {
                return Err(ArithmeticError::DivideByZero);
            }
            let numerator = left
                .coefficient
                .checked_mul(power_of_ten(right.scale)?)
                .ok_or(ArithmeticError::Overflow)?;
            let signed_denominator = right
                .coefficient
                .checked_mul(power_of_ten(left.scale)?)
                .ok_or(ArithmeticError::Overflow)?;
            if signed_denominator < 0 {
                quantize(
                    numerator.checked_neg().ok_or(ArithmeticError::Overflow)?,
                    signed_denominator
                        .checked_neg()
                        .ok_or(ArithmeticError::Overflow)?,
                )
            } else {
                quantize(numerator, signed_denominator)
            }
        }
    }
}

fn percent(value: DecimalValue) -> Result<DecimalValue, ArithmeticError> {
    let scale = value
        .scale
        .checked_add(2)
        .ok_or(ArithmeticError::Overflow)?;
    quantize(value.coefficient, power_of_ten(scale)?)
}

fn power_of_ten(power: u8) -> Result<i128, ArithmeticError> {
    let mut value = 1i128;
    for _ in 0..power {
        value = value.checked_mul(10).ok_or(ArithmeticError::Overflow)?;
    }
    Ok(value)
}

fn quantize(numerator: i128, denominator: i128) -> Result<DecimalValue, ArithmeticError> {
    if denominator <= 0 {
        return Err(ArithmeticError::Overflow);
    }
    for candidate_scale in (0..=MAX_SCALE).rev() {
        let Some(scaled) = numerator.checked_mul(power_of_ten(candidate_scale)?) else {
            continue;
        };
        let quotient = scaled / denominator;
        let remainder = scaled % denominator;
        let Some(doubled_remainder) = remainder.abs().checked_mul(2) else {
            continue;
        };
        let rounded = if doubled_remainder >= denominator {
            quotient.checked_add(if scaled < 0 { -1 } else { 1 })
        } else {
            Some(quotient)
        };
        let Some(rounded) = rounded else {
            continue;
        };
        let value = DecimalValue {
            coefficient: rounded,
            scale: candidate_scale,
        }
        .normalized();
        if digit_glyphs(value).is_some_and(|count| count <= MAX_DIGIT_GLYPHS) {
            return Ok(value);
        }
    }
    Err(ArithmeticError::Overflow)
}

fn digit_glyphs(value: DecimalValue) -> Option<usize> {
    let magnitude = value.coefficient.checked_abs()?;
    let digits = decimal_digits(magnitude);
    Some(if usize::from(value.scale) >= digits {
        1 + usize::from(value.scale)
    } else {
        digits
    })
}

fn decimal_digits(mut magnitude: i128) -> usize {
    if magnitude == 0 {
        return 1;
    }
    let mut digits = 0;
    while magnitude != 0 {
        digits += 1;
        magnitude /= 10;
    }
    digits
}

fn render(value: DecimalValue) -> Option<DisplayText> {
    let value = value.normalized();
    if digit_glyphs(value)? > MAX_DIGIT_GLYPHS {
        return None;
    }
    let negative = value.coefficient < 0;
    let mut magnitude = value.coefficient.checked_abs()?;
    let mut reversed = [0u8; MAX_DIGIT_GLYPHS];
    let mut digit_len = 0usize;
    loop {
        reversed[digit_len] = b'0' + u8::try_from(magnitude % 10).ok()?;
        digit_len += 1;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }

    let mut output = [0u8; DISPLAY_CAPACITY];
    let mut len = 0usize;
    if negative {
        output[len] = b'-';
        len += 1;
    }
    let scale = usize::from(value.scale);
    if scale == 0 {
        for index in (0..digit_len).rev() {
            output[len] = reversed[index];
            len += 1;
        }
    } else if digit_len <= scale {
        output[len] = b'0';
        output[len + 1] = b'.';
        len += 2;
        for _ in 0..(scale - digit_len) {
            output[len] = b'0';
            len += 1;
        }
        for index in (0..digit_len).rev() {
            output[len] = reversed[index];
            len += 1;
        }
    } else {
        for index in (0..digit_len).rev() {
            if index + 1 == scale {
                output[len] = b'.';
                len += 1;
            }
            output[len] = reversed[index];
            len += 1;
        }
    }
    Some(DisplayText {
        bytes: output,
        len: len as u8,
    })
}

const fn digit_byte(key: DecoyKey) -> u8 {
    match key {
        DecoyKey::Zero => b'0',
        DecoyKey::One => b'1',
        DecoyKey::TwoDown => b'2',
        DecoyKey::Three => b'3',
        DecoyKey::FourLeft => b'4',
        DecoyKey::Five => b'5',
        DecoyKey::SixRight => b'6',
        DecoyKey::Seven => b'7',
        DecoyKey::EightUp => b'8',
        DecoyKey::Nine => b'9',
        DecoyKey::Decimal
        | DecoyKey::Plus
        | DecoyKey::Minus
        | DecoyKey::Multiply
        | DecoyKey::Divide
        | DecoyKey::Percent
        | DecoyKey::CeDelete
        | DecoyKey::CancelBack
        | DecoyKey::EqualsConfirmEnter => b'0',
    }
}

const fn operator(key: DecoyKey) -> BinaryOperator {
    match key {
        DecoyKey::Plus => BinaryOperator::Add,
        DecoyKey::Minus => BinaryOperator::Subtract,
        DecoyKey::Multiply => BinaryOperator::Multiply,
        DecoyKey::Divide => BinaryOperator::Divide,
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
        | DecoyKey::EqualsConfirmEnter => BinaryOperator::Add,
    }
}
