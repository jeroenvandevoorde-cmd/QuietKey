//! Dependency-free bounded calculator decoy.
//!
//! HOST REFERENCE ONLY -- NOT A WALLET -- NO TARGET, DISPLAY, KEYPAD,
//! PRIVILEGE-CONTAINMENT, PERFORMANCE, PRODUCTION, OR GATE CLAIM.
//!
//! This crate implements only the QK-DEC-142 P0.1 calculator state machine.
//! It has no wallet-entry gesture, secret type, wallet or card state, device
//! access, process control, IPC, cryptography, logging, persistence, clock, or
//! randomness surface.

#![forbid(unsafe_code)]

mod calculator;
mod process;

pub use calculator::{
    ApplyOutcome, Calculator, CalculatorPhase, CalculatorRejection, DecoyKey, DisplayText,
    ALL_DECOY_KEYS, DISPLAY_CAPACITY, MAX_DIGIT_GLYPHS,
};
pub use process::DecoyHostProcess;
