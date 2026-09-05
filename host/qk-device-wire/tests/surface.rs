#![allow(clippy::panic, clippy::unwrap_used)]

const LIB: &str = include_str!("../src/lib.rs");
const WIRE: &str = include_str!("../src/wire.rs");
const STREAM: &str = include_str!("../src/stream.rs");
const SESSION: &str = include_str!("../src/session.rs");
const WIPE: &str = include_str!("../src/wipe.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn dependency_free_manifest_and_host_only_surface_are_pinned() {
    assert!(MANIFEST.contains("[features]\nfuzzing = []\nlegacy-normal-factor-fixture = []"));
    let dependency_tail = MANIFEST.split("[dependencies]").nth(1).unwrap();
    assert!(dependency_tail.trim().is_empty());
    for forbidden in [
        "std::fs",
        "std::net",
        "std::process",
        "std::time",
        "getrandom",
        "rand::",
        "println!",
        "eprintln!",
    ] {
        assert!(!LIB.contains(forbidden));
        assert!(!WIRE.contains(forbidden));
        assert!(!STREAM.contains(forbidden));
        assert!(!SESSION.contains(forbidden));
    }
    assert!(LIB.contains("HOST REFERENCE ONLY"));
    assert!(LIB.contains("pub const HEADER_BYTES: usize = 16;"));
    assert!(LIB.contains("pub const MAX_BODY_BYTES: usize = 2_097_152;"));
    assert!(LIB.contains("pub const MAX_CARD_APDU_REQUEST_BODY_BYTES: usize = 221;"));
    assert!(LIB.contains("pub const MAX_CARD_APDU_RESPONSE_BODY_BYTES: usize = 218;"));
}

#[test]
fn unsafe_is_confined_to_the_single_reviewed_wipe_boundary() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert!(LIB.contains("#[allow(unsafe_code)]\nmod wipe;"));
    assert!(!WIRE.contains("unsafe"));
    assert!(!STREAM.contains("unsafe"));
    assert!(!SESSION.contains("unsafe"));
    assert_eq!(WIPE.matches("unsafe { ptr::write_volatile").count(), 2);
    assert_eq!(WIPE.matches("#[allow(unsafe_code)]").count(), 2);
    assert!(WIPE.contains("compiler_fence(Ordering::SeqCst)"));
    assert!(WIPE.contains("let capacity = self.0.capacity();"));
    assert!(WIPE.contains("allocation(self.0.as_mut_ptr(), capacity);"));
}

#[test]
fn secret_bearing_owners_do_not_expose_debug_clone_or_raw_constructors() {
    for source in [WIRE, STREAM] {
        assert!(!source.contains("impl Debug for ReceivedFrame"));
        assert!(!source.contains("impl Clone for ReceivedFrame"));
        assert!(!source.contains("impl Debug for NormalFactorRef"));
        assert!(!source.contains("impl Debug for BodyRef"));
    }
    assert!(STREAM.contains("pub struct ReceivedFrame"));
    assert!(WIRE.contains("pub struct NormalFactorRef<'a>"));
    assert!(WIRE.contains("pub enum BodyRef<'a>"));
    assert!(!LIB.contains("pub mod wipe"));
}

#[test]
fn parser_precedence_and_closed_names_are_source_pinned() {
    let ordered_checks = [
        "if bytes[0..4] != MAGIC",
        "if bytes[4] != VERSION",
        "let capability = Capability::parse(bytes[5])?",
        "if capability != expected_capability",
        "let kind = MessageKind::parse(capability, bytes[6])?",
        "if bytes[7] != 0",
        "if sequence == 0",
        "if body_len as usize > kind.body_cap()",
    ];
    let mut position = 0usize;
    for check in ordered_checks {
        let found = WIRE[position..].find(check).unwrap() + position;
        assert!(found >= position);
        position = found + check.len();
    }
    for name in [
        "SequenceReplay",
        "SequenceRegression",
        "SequenceSkipped",
        "SequenceExhausted",
        "ResponseSequenceMismatch",
        "ResponseKindMismatch",
        "FinalFlagMismatch",
        "TransferIncomplete",
        "DeviceRejected",
        "LegacyNormalFactorRejected",
    ] {
        assert!(LIB.contains(name));
    }
}
