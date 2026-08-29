//! Exact public, dependency, capability, and secret-ownership boundaries.

use qk_kit::{KitError, FALLBACK_SYMBOLS, FRAME_LEN, QR_CORE_SIZE, QR_PACKED_BYTES, QR_SIZE};

const LIB: &str = include_str!("../src/lib.rs");
const FRAME: &str = include_str!("../src/frame.rs");
const FALLBACK: &str = include_str!("../src/fallback.rs");
const QR: &str = include_str!("../src/qr.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const SECRET: &str = include_str!("../src/secret.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

fn public_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect()
}

#[test]
fn public_surface_is_exactly_the_fixed_codec_and_opaque_owner() {
    assert_eq!(
        public_lines(LIB),
        [
            "pub use fallback::{decode_fallback, encode_fallback};",
            "pub use frame::{combine_frames, encode_frame, frame_metadata};",
            "pub use qr::encode_qr;",
            "pub const FRAME_LEN: usize = 142;",
            "pub const FALLBACK_SYMBOLS: usize = 228;",
            "pub const QR_CORE_SIZE: usize = 57;",
            "pub const QR_SIZE: usize = 65;",
            "pub const QR_PACKED_BYTES: usize = 529;",
            "pub enum KitError {",
            "pub enum ShareIndex {",
            "pub const fn as_u8(self) -> u8 {",
            "pub struct FrameMetadata {",
            "pub share_index: ShareIndex,",
            "pub wallet_id: [u8; 32],",
            "pub struct QrMetadata {",
            "pub mask: u8,",
            "pub penalties: [u32; 8],",
            "pub struct RecoveredKitPayload {",
        ],
        "complete crate-root item, field, constant, and method surface"
    );
    assert_eq!(
        public_lines(FRAME),
        [
            "pub fn encode_frame(",
            "pub fn frame_metadata(frame: &[u8]) -> Result<FrameMetadata, KitError> {",
            "pub fn combine_frames(",
        ]
    );
    assert_eq!(
        public_lines(FALLBACK),
        ["pub fn encode_fallback(", "pub fn decode_fallback("]
    );
    assert_eq!(
        public_lines(QR),
        [
            "pub fn encode_qr(frame: &[u8], output: &mut [u8; 529]) -> Result<QrMetadata, KitError> {"
        ]
    );
    assert!(public_lines(SHA256).is_empty());
    assert!(public_lines(SECRET).is_empty());

    for forbidden in [
        "pub mod ",
        "pub fn generate",
        "pub fn random",
        "pub fn render",
        "pub fn scan",
        "pub fn recover",
        "pub fn payload",
        "pub fn share",
        "pub fn bytes",
        "pub fn serialize",
        "pub fn normalize",
        "pub fn sha256",
        "pub fn reed_solomon",
        "pub fn select_mask",
    ] {
        assert!(
            !LIB.contains(forbidden),
            "forbidden public surface {forbidden}"
        );
    }
}

#[test]
fn error_vocabulary_and_fixed_display_are_exact() {
    let cases = [
        (KitError::FrameLength, "FrameLength"),
        (KitError::FrameChecksum, "FrameChecksum"),
        (KitError::InvalidMagic, "InvalidMagic"),
        (KitError::UnsupportedVersion, "UnsupportedVersion"),
        (KitError::InvalidShareIndex, "InvalidShareIndex"),
        (KitError::FallbackLength, "FallbackLength"),
        (KitError::MalformedSymbol, "MalformedSymbol"),
        (KitError::NonCanonicalPadding, "NonCanonicalPadding"),
        (KitError::DuplicateShare, "DuplicateShare"),
        (KitError::SameShareIndex, "SameShareIndex"),
        (KitError::WalletMismatch, "WalletMismatch"),
    ];
    for (error, name) in cases {
        assert_eq!(error.to_string(), name);
        assert_eq!(LIB.matches(&format!("    {name},")).count(), 1);
        assert_eq!(
            LIB.matches(&format!("Self::{name} => \"{name}\"")).count(),
            1
        );
    }
}

#[test]
fn geometry_profile_and_wire_constants_are_locked() {
    assert_eq!(FRAME_LEN, 142);
    assert_eq!(FALLBACK_SYMBOLS, 228);
    assert_eq!(QR_CORE_SIZE, 57);
    assert_eq!(QR_SIZE, 65);
    assert_eq!(QR_PACKED_BYTES, 529);

    for required in [
        "const MAGIC: [u8; 4] = *b\"QKKS\";",
        "const VERSION: u8 = 1;",
        "const SHARE_LEN: usize = 96;",
        "const CHECKSUM_LEN: usize = 8;",
        "const CHECKSUM_DOMAIN: &[u8] = b\"QuietKey/KitShare/v1\";",
        "const ALPHABET: &[u8; 32] = b\"23456789abcdefghijkmnpqrstuvwxyz\";",
        "const PAD_BITS: usize = FALLBACK_BITS - FRAME_BITS;",
    ] {
        assert!(
            [FRAME, FALLBACK]
                .iter()
                .any(|source| source.contains(required)),
            "wire pin {required}"
        );
    }
    for required in [
        "const DATA_CODEWORDS: usize = 154;",
        "const ECC_CODEWORDS_PER_BLOCK: usize = 24;",
        "const BLOCK_COUNT: usize = 8;",
        "const SHORT_BLOCK_COUNT: usize = 6;",
        "const SHORT_DATA_CODEWORDS: usize = 19;",
        "const LONG_DATA_CODEWORDS: usize = 20;",
        "const TOTAL_CODEWORDS: usize = 346;",
        "const CORE_SIDE: usize = 57;",
        "const QUIET_ZONE: usize = 4;",
        "append_bits(0b0100, 4, &mut result, &mut bit_length);",
        "append_bits(FRAME_LEN as u32, 16, &mut result, &mut bit_length);",
        "result[byte_length] = if use_first_pad { 0xec } else { 0x11 };",
    ] {
        assert!(QR.contains(required), "QR profile pin {required}");
    }
}

#[test]
fn combined_payload_and_parsed_shares_expose_no_secret_surface_or_traits() {
    let owner_start = LIB
        .find("pub struct RecoveredKitPayload {")
        .expect("opaque owner definition");
    let owner_tail = &LIB[owner_start..];
    let owner_end = owner_tail.find("\n}\n").expect("owner terminator") + 2;
    let owner_definition = &owner_tail[..owner_end];
    assert!(owner_definition.contains("_bytes: secret::Secret<96>,"));
    assert!(!owner_definition
        .lines()
        .skip(1)
        .any(|line| line.trim_start().starts_with("pub ")));

    let owner_attributes = LIB[..owner_start]
        .rsplit("\n\n")
        .next()
        .expect("owner attributes");
    assert!(!owner_attributes.contains("#[derive"));
    for trait_name in ["Clone", "Copy", "Debug", "Display", "PartialEq", "Eq"] {
        assert!(
            !LIB.contains(&format!("impl {trait_name} for RecoveredKitPayload")),
            "opaque owner trait {trait_name}"
        );
    }
    for forbidden in [
        "pub fn take",
        "pub fn as_bytes",
        "pub fn bytes",
        "pub fn payload",
        "pub fn share",
        "pub fn serialize",
        "pub fn snapshot",
    ] {
        assert!(
            !owner_tail.contains(forbidden),
            "opaque owner method {forbidden}"
        );
    }

    assert!(FRAME.contains("pub(crate) struct ValidatedShare {"));
    assert!(FRAME.contains("share: Secret<SHARE_LEN>,"));
    assert!(!FRAME.contains("pub struct ValidatedShare"));
    assert!(!FRAME.contains("pub fn share(&self)"));
    assert!(SECRET.contains("pub(crate) struct Secret<const N: usize>"));
    assert!(!SECRET.contains("pub struct Secret"));
    assert!(!SECRET.contains("#[derive"));
    for trait_name in ["Clone", "Copy", "Debug", "Display", "PartialEq", "Eq"] {
        assert!(
            !SECRET.contains(&format!("impl<const N: usize> {trait_name} for Secret")),
            "secret owner trait {trait_name}"
        );
    }
}

#[test]
fn production_is_fixed_memory_and_has_no_io_logging_rng_network_or_adjacent_capability() {
    for source in [LIB, FRAME, FALLBACK, QR, SHA256, SECRET] {
        for forbidden in [
            "Vec<",
            "Vec::",
            "vec![",
            "String",
            "Box<",
            "Box::",
            "Rc<",
            "Arc<",
            "HashMap",
            "BTreeMap",
            "alloc::",
            "std::fs",
            "std::io",
            "std::net",
            "std::env",
            "std::process",
            "File::",
            "OpenOptions",
            "println!",
            "eprintln!",
            "dbg!",
            "log::",
            "tracing::",
            "SystemTime",
            "getrandom",
            "OsRng",
            "rand::",
            "random(",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "image::",
            "camera::",
            "ocr::",
            "pub fn render",
            "pub fn scan",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden production token {forbidden}"
            );
        }
    }

    for source in [LIB, FRAME, FALLBACK, QR, SHA256] {
        for forbidden in ["unsafe fn", "unsafe impl", "unsafe {"] {
            assert!(
                !source.contains(forbidden),
                "unsafe outside secret boundary {forbidden}"
            );
        }
    }
    assert!(LIB.contains("#![deny(unsafe_code)]"));

    let dependency_tail = MANIFEST
        .split_once("[dependencies]\n")
        .expect("dependency section")
        .1;
    assert!(dependency_tail.trim().is_empty());
    for forbidden in [
        "[dev-dependencies]",
        "[build-dependencies]",
        "build =",
        "git =",
        "path =",
        "registry =",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "manifest surface {forbidden}"
        );
    }
}

#[test]
fn volatile_wipe_boundary_and_output_commit_order_are_locked() {
    assert_eq!(SECRET.matches("#[inline(never)]").count(), 2);
    assert_eq!(
        SECRET
            .matches("unsafe { ptr::write_volatile(byte, 0) }")
            .count(),
        1
    );
    assert_eq!(
        SECRET
            .matches("unsafe { ptr::write_volatile(word, 0) }")
            .count(),
        1
    );
    assert_eq!(
        SECRET.matches("compiler_fence(Ordering::SeqCst)").count(),
        2
    );
    assert_eq!(SECRET.matches("unsafe {").count(), 2);
    assert_eq!(SECRET.matches("#![allow(unsafe_code)]").count(), 1);
    assert!(SECRET.contains("#![deny(unsafe_op_in_unsafe_fn)]"));
    assert!(SECRET.contains("impl<const N: usize> Drop for Secret<N>"));
    assert!(SECRET.contains("wipe(&mut self.bytes);"));

    let take_start = SECRET
        .find("pub(crate) fn take(bytes: &mut [u8; N]) -> Self")
        .expect("take constructor");
    let take = &SECRET[take_start..];
    let copy = take
        .find("let owned = Self { bytes: *bytes };")
        .expect("copy");
    let wipe = take.find("wipe(bytes);").expect("source wipe");
    assert!(copy < wipe);

    for required in [
        "let owned_share = Secret::copy_from(&share);",
        "wipe(&mut share);",
        "Ok(RecoveredKitPayload::take(&mut payload))",
        "wipe(&mut digest);",
        "wipe(&mut expected);",
    ] {
        assert!(FRAME.contains(required), "frame cleanup route {required}");
    }
    for required in [
        "wipe(&mut candidate);",
        "Err(KitError::MalformedSymbol)",
        "Err(KitError::NonCanonicalPadding)",
    ] {
        assert!(
            FALLBACK.contains(required),
            "fallback cleanup route {required}"
        );
    }
    for required in [
        "wipe_u32(&mut self.state);",
        "wipe(&mut self.buffer);",
        "wipe_u32(&mut schedule);",
        "wipe_u32(&mut working);",
        "wipe_u32(&mut scratch);",
    ] {
        assert!(SHA256.contains(required), "hash cleanup route {required}");
    }

    let qr_validate = QR
        .find("crate::frame::validate(frame)?;")
        .expect("QR validates before work");
    let qr_commit = QR
        .find("output.copy_from_slice(&packed);")
        .expect("QR output commit");
    assert!(qr_validate < qr_commit);
    let fallback_validate = FALLBACK
        .find("frame::validate(frame_bytes)?;")
        .expect("fallback validates before work");
    let fallback_commit = FALLBACK
        .find("output.copy_from_slice(&candidate);")
        .expect("fallback output commit");
    assert!(fallback_validate < fallback_commit);
}
