//! Disposable host-only workflow policy model.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//! HOST policy model only.
//!
//! The single model is the transaction authorization policy in
//! [`transaction_policy`]: opaque payload-free states, deterministic
//! public events, structured transition errors, and a total transition
//! function whose outcome type always exposes the security result and
//! which is fail-closed over the currently declared state/event
//! semantics only, assuming successful host execution: allocation
//! failure, panic or abort, process termination, persistence, boot
//! recovery, and target behavior are out of scope.
//!
//! This crate contains no secret bytes, wallet data, cryptography,
//! parsing, file or device access, clocks, randomness, logging, network,
//! environment access, threads, processes, FFI, persistence, or hardware
//! code. See [`transaction_policy`] for the canonical scope disclaimer.

#![forbid(unsafe_code)]

pub mod transaction_policy;
