//! One-to-one QK-TST-BENCH-002 assertion-set check.

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Assertion {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
}

impl Assertion {
    pub const ALL: [Self; 7] = [
        Self::A,
        Self::B,
        Self::C,
        Self::D,
        Self::E,
        Self::F,
        Self::G,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    WrongCount,
    DuplicateAssertion,
    MissingAssertion,
}

/// Requires exactly one registration for every QK-TST-BENCH-002 assertion.
pub fn assert_complete_assertion_set(assertions: &[Assertion]) -> Result<(), RegistrationError> {
    if assertions.len() != Assertion::ALL.len() {
        return Err(RegistrationError::WrongCount);
    }
    let mut seen = [false; 7];
    for assertion in assertions {
        let index = *assertion as usize;
        if seen[index] {
            return Err(RegistrationError::DuplicateAssertion);
        }
        seen[index] = true;
    }
    if seen.iter().any(|present| !present) {
        return Err(RegistrationError::MissingAssertion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{assert_complete_assertion_set, Assertion, RegistrationError};

    #[test]
    fn exact_a_through_g_set_is_complete_in_any_order() {
        assert_eq!(assert_complete_assertion_set(&Assertion::ALL), Ok(()));
        assert_eq!(
            assert_complete_assertion_set(&[
                Assertion::G,
                Assertion::F,
                Assertion::E,
                Assertion::D,
                Assertion::C,
                Assertion::B,
                Assertion::A,
            ]),
            Ok(())
        );
    }

    #[test]
    fn count_and_duplicates_are_distinct() {
        assert_eq!(
            assert_complete_assertion_set(&Assertion::ALL[..6]),
            Err(RegistrationError::WrongCount)
        );
        assert_eq!(
            assert_complete_assertion_set(&[
                Assertion::A,
                Assertion::B,
                Assertion::C,
                Assertion::D,
                Assertion::E,
                Assertion::F,
                Assertion::F,
            ]),
            Err(RegistrationError::DuplicateAssertion)
        );
    }
}
