//! Real HOST child owner for the calculator-only decoy address space.

use crate::{Calculator, CalculatorPhase, DisplayText};

/// One live calculator decoy process state.
///
/// No wallet gesture or mock-device byte protocol is introduced. The
/// supervisor owns the inherited keypad/display descriptor facts and ends the
/// process before granting any product capability.
pub struct DecoyHostProcess {
    calculator: Calculator,
}

impl DecoyHostProcess {
    /// Construct the exact cleared calculator state before the process waits.
    pub const fn new() -> Self {
        Self {
            calculator: Calculator::new(),
        }
    }

    /// Exact current calculator phase for the bounded process test seam.
    pub const fn phase(&self) -> CalculatorPhase {
        self.calculator.phase()
    }

    /// Exact current nonsecret display fact for the bounded process test seam.
    pub const fn display(&self) -> DisplayText {
        self.calculator.display()
    }

    /// Wait indefinitely for supervisor termination without accepting a
    /// controller, wallet-entry gesture, keypad byte grammar, or restart.
    pub fn wait(self) -> ! {
        let _owner = self;
        loop {
            std::thread::park();
        }
    }
}

impl Default for DecoyHostProcess {
    fn default() -> Self {
        Self::new()
    }
}
