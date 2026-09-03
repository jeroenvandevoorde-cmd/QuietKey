//! Exact dependency, authority, and public-boundary locks.

const LIB: &str = include_str!("../src/lib.rs");
const APDU: &str = include_str!("../src/apdu.rs");
const RECORD: &str = include_str!("../src/record.rs");
const SESSION: &str = include_str!("../src/session.rs");
const WIPE: &str = include_str!("../src/wipe.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn crate_is_dependency_free_host_reference_only() {
    let dependency_tail = MANIFEST.split_once("[dependencies]\n").unwrap().1;
    assert!(dependency_tail.trim().is_empty());
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("build ="));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("path ="));
    assert!(LIB.contains("HOST REFERENCE ONLY -- NOT AN APPLET OR DEVICE DRIVER"));
}

#[test]
fn public_root_surface_is_exact() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub use apdu::{",
            "pub use record::{",
            "pub use session::{allowed_operations, Lifecycle, SessionTracker};",
            "pub use wipe::{reset_wiped_bytes, wiped_bytes};",
            "pub const APPLET_AID: [u8; 6] = [0xf0, 0x51, 0x4b, 0x32, 0x42, 0x01];",
            "pub const PROTOCOL_VERSION: u8 = 1;",
            "pub const RECORD_VERSION: u8 = 1;",
            "pub const ROLE_KEY_CARD_B: u8 = 2;",
            "pub const RECORD_BYTES: usize = 781;",
            "pub const MAX_WRITE_CHUNK_BYTES: usize = 192;",
            "pub const WRITE_CHUNK_COUNT: usize = 5;",
            "pub const DESCRIPTOR_BYTES: usize = 306;",
            "pub const RAW_XPUB_BYTES: usize = 78;",
            "pub const RAW_XPRV_BYTES: usize = 78;",
            "pub const MAX_EXCHANGES: u16 = 128;",
            "pub const MAX_AGGREGATE_BYTES: usize = 65_536;",
            "pub const MAX_SIGNATURES: u8 = 100;",
            "pub const MAX_CHILD_INDEX: u32 = 65_535;",
            "pub const MAX_REQUEST_BYTES: usize = 221;",
            "pub const MAX_RESPONSE_BYTES: usize = 218;",
        ]
    );
    assert!(!LIB.contains("pub mod "));
    assert!(LIB.contains("#[cfg(feature = \"fuzzing\")]\n#[doc(hidden)]\npub use wipe"));
}

#[test]
fn source_has_no_io_persistence_crypto_or_allocation_surface() {
    for source in [LIB, APDU, RECORD, SESSION, WIPE] {
        for forbidden in [
            "std::fs",
            "std::net",
            "std::process",
            "Command::new",
            "OpenOptions",
            "TcpStream",
            "UdpSocket",
            "extern crate",
            "Vec<",
            "String",
            "Box<",
            "Sha256",
            "Sha512",
            "Hmac",
            "secp256k1::",
            "rand::",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden source surface: {forbidden}"
            );
        }
    }
    assert!(!SESSION.contains("impl Clone for SessionTracker"));
    assert!(!SESSION.contains("impl Copy for SessionTracker"));
    assert!(!SESSION.contains("impl Debug for SessionTracker"));
    for secret_view in [
        "pub struct EnvelopeRef<'a>",
        "pub enum CommandRef<'a>",
        "pub enum ResponseRef<'a>",
        "pub struct SignRequest<'a>",
    ] {
        let prefix = APDU
            .split_once(secret_view)
            .expect("secret-bearing APDU view exists")
            .0;
        let derive = prefix
            .rsplit_once("#[derive(")
            .expect("secret-bearing APDU view has derives")
            .1
            .split_once(")]")
            .expect("derive closes")
            .0;
        assert!(!derive.contains("Debug"), "Debug exposed by {secret_view}");
    }
    for redacted in [
        "EnvelopeRef(REDACTED)",
        "CommandRef(REDACTED)",
        "ResponseRef(REDACTED)",
        "SignRequest(REDACTED)",
    ] {
        assert!(
            APDU.contains(redacted),
            "missing redacted Debug: {redacted}"
        );
    }
    for secret_view in ["pub struct XprvRef<'a>", "pub struct RecordRef<'a>"] {
        let prefix = RECORD
            .split_once(secret_view)
            .expect("secret-bearing record view exists")
            .0;
        let derive = prefix
            .rsplit_once("#[derive(")
            .expect("secret-bearing record view has derives")
            .1
            .split_once(")]")
            .expect("derive closes")
            .0;
        assert!(!derive.contains("Debug"), "Debug exposed by {secret_view}");
    }
    for redacted in ["XprvRef(REDACTED)", "RecordRef(REDACTED)"] {
        assert!(
            RECORD.contains(redacted),
            "missing redacted Debug: {redacted}"
        );
    }
    assert_eq!(
        WIPE.matches("unsafe { ptr::write_volatile(byte, 0) }")
            .count(),
        1
    );
    assert_eq!(WIPE.matches("compiler_fence(Ordering::SeqCst)").count(), 1);
    assert_eq!(WIPE.matches("unsafe {").count(), 1);
}
