//! Frozen M22 public surface, cap arithmetic, and fixed-memory source restrictions.

use qk_bbqr::{
    BbqrError, DecodedFrame, Reassembler, ReassemblyProgress, MAX_BODY_SYMBOLS, MAX_DECLARED_PARTS,
    MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_SUBMISSIONS, MAX_TOTAL_DECODED_BYTES,
};

const LIB: &str = include_str!("../src/lib.rs");
const BASE32: &str = include_str!("../src/base32.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

const HEADER_TEXT_BYTES: usize = 8;
const _: [(); MAX_FRAME_TEXT_BYTES] = [(); HEADER_TEXT_BYTES + MAX_BODY_SYMBOLS];
const _: [(); MAX_PART_DECODED_BYTES] = [(); MAX_BODY_SYMBOLS * 5 / 8];
const _: [(); MAX_SUBMISSIONS] = [(); MAX_DECLARED_PARTS * 2];
const _: [(); 262_144] = [(); MAX_TOTAL_DECODED_BYTES];

#[test]
fn public_surface_is_exactly_caps_errors_metadata_and_four_operations() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub const MAX_DECLARED_PARTS: usize = 256;",
            "pub const MAX_FRAME_TEXT_BYTES: usize = 4_296;",
            "pub const MAX_BODY_SYMBOLS: usize = 4_288;",
            "pub const MAX_PART_DECODED_BYTES: usize = 2_680;",
            "pub const MAX_TOTAL_DECODED_BYTES: usize = 262_144;",
            "pub const MAX_SUBMISSIONS: usize = 512;",
            "pub enum BbqrError {",
            "pub struct DecodedFrame {",
            "pub declared_parts: u16,",
            "pub part_index: u16,",
            "pub decoded_len: usize,",
            "pub struct ReassemblyProgress {",
            "pub declared_parts: u16,",
            "pub received_parts: u16,",
            "pub identical_duplicates: u16,",
            "pub submissions: u16,",
            "pub decoded_bytes: usize,",
            "pub was_duplicate: bool,",
            "pub complete: bool,",
            "pub fn encoded_part_count(payload_len: usize, non_final_part_len: usize) -> Result<u16, BbqrError> {",
            "pub fn encode_frame(",
            "pub fn decode_frame(",
            "pub struct Reassembler<'a> {",
            "pub fn new(output: &'a mut [u8; MAX_TOTAL_DECODED_BYTES]) -> Self {",
            "pub fn submit(&mut self, frame: &[u8]) -> Result<ReassemblyProgress, BbqrError> {",
            "pub fn payload(&self) -> Result<&[u8], BbqrError> {",
        ],
        "complete public item, field, constant, and method surface"
    );

    let error_names = [
        "EmptyPayload",
        "PayloadTooLarge",
        "InvalidNonFinalPartLength",
        "TooManyParts",
        "PartIndexOutOfRange",
        "FrameTooShort",
        "FrameTooLarge",
        "InvalidMagic",
        "UnsupportedEncoding",
        "UnsupportedFileType",
        "InvalidDeclaredPartCount",
        "DeclaredPartCountExceeded",
        "InvalidPartIndex",
        "EmptyPart",
        "Base32PaddingForbidden",
        "MalformedBase32Symbol",
        "NonCanonicalBase32Length",
        "NonCanonicalBase32Padding",
        "NonFinalPartLengthNotMultipleOfFive",
        "StreamEncodingMismatch",
        "StreamFileTypeMismatch",
        "StreamPartCountMismatch",
        "NonUniformPartLength",
        "FinalPartTooLarge",
        "TotalDecodedSizeExceeded",
        "ConflictingDuplicate",
        "DuplicateWorkExceeded",
        "SubmissionWorkExceeded",
        "Incomplete",
        "AlreadyComplete",
    ];
    for name in error_names {
        assert_eq!(
            LIB.matches(&format!("    {name},")).count(),
            1,
            "error variant {name}"
        );
        assert_eq!(
            BbqrError::to_string(&error_by_name(name)),
            name,
            "fixed attacker-independent Display text"
        );
    }

    let _: Option<DecodedFrame> = None;
    let _: Option<ReassemblyProgress> = None;
    let _: Option<Reassembler<'_>> = None;

    for forbidden in [
        "pub mod ",
        "pub use ",
        "impl Default for Reassembler",
        "pub fn reset(",
        "pub fn restart(",
        "pub fn base32",
        "pub fn compress",
        "pub fn decompress",
        "pub fn render",
        "pub fn scan",
        "pub fn size_for_qr",
        "DEFAULT_PART",
    ] {
        assert!(!LIB.contains(forbidden), "forbidden surface {forbidden}");
    }
}

fn error_by_name(name: &str) -> BbqrError {
    match name {
        "EmptyPayload" => BbqrError::EmptyPayload,
        "PayloadTooLarge" => BbqrError::PayloadTooLarge,
        "InvalidNonFinalPartLength" => BbqrError::InvalidNonFinalPartLength,
        "TooManyParts" => BbqrError::TooManyParts,
        "PartIndexOutOfRange" => BbqrError::PartIndexOutOfRange,
        "FrameTooShort" => BbqrError::FrameTooShort,
        "FrameTooLarge" => BbqrError::FrameTooLarge,
        "InvalidMagic" => BbqrError::InvalidMagic,
        "UnsupportedEncoding" => BbqrError::UnsupportedEncoding,
        "UnsupportedFileType" => BbqrError::UnsupportedFileType,
        "InvalidDeclaredPartCount" => BbqrError::InvalidDeclaredPartCount,
        "DeclaredPartCountExceeded" => BbqrError::DeclaredPartCountExceeded,
        "InvalidPartIndex" => BbqrError::InvalidPartIndex,
        "EmptyPart" => BbqrError::EmptyPart,
        "Base32PaddingForbidden" => BbqrError::Base32PaddingForbidden,
        "MalformedBase32Symbol" => BbqrError::MalformedBase32Symbol,
        "NonCanonicalBase32Length" => BbqrError::NonCanonicalBase32Length,
        "NonCanonicalBase32Padding" => BbqrError::NonCanonicalBase32Padding,
        "NonFinalPartLengthNotMultipleOfFive" => BbqrError::NonFinalPartLengthNotMultipleOfFive,
        "StreamEncodingMismatch" => BbqrError::StreamEncodingMismatch,
        "StreamFileTypeMismatch" => BbqrError::StreamFileTypeMismatch,
        "StreamPartCountMismatch" => BbqrError::StreamPartCountMismatch,
        "NonUniformPartLength" => BbqrError::NonUniformPartLength,
        "FinalPartTooLarge" => BbqrError::FinalPartTooLarge,
        "TotalDecodedSizeExceeded" => BbqrError::TotalDecodedSizeExceeded,
        "ConflictingDuplicate" => BbqrError::ConflictingDuplicate,
        "DuplicateWorkExceeded" => BbqrError::DuplicateWorkExceeded,
        "SubmissionWorkExceeded" => BbqrError::SubmissionWorkExceeded,
        "Incomplete" => BbqrError::Incomplete,
        "AlreadyComplete" => BbqrError::AlreadyComplete,
        _ => unreachable!(),
    }
}

#[test]
fn cap_values_and_const_arithmetic_are_exact() {
    assert_eq!(MAX_DECLARED_PARTS, 256);
    assert_eq!(MAX_FRAME_TEXT_BYTES, 4_296);
    assert_eq!(MAX_BODY_SYMBOLS, 4_288);
    assert_eq!(MAX_PART_DECODED_BYTES, 2_680);
    assert_eq!(MAX_TOTAL_DECODED_BYTES, 262_144);
    assert_eq!(MAX_SUBMISSIONS, 512);

    for pin in [
        "const HEADER_LEN: usize = 8;",
        "const ENCODING: u8 = b'2';",
        "const FILE_TYPE: u8 = b'P';",
        "const _: () = assert!(HEADER_LEN + MAX_BODY_SYMBOLS == MAX_FRAME_TEXT_BYTES);",
        "const _: () = assert!(MAX_BODY_SYMBOLS * 5 / 8 == MAX_PART_DECODED_BYTES);",
        "const _: () = assert!(MAX_DECLARED_PARTS * 2 == MAX_SUBMISSIONS);",
    ] {
        assert!(LIB.contains(pin), "source arithmetic pin {pin}");
    }
    assert_eq!(MAX_PART_DECODED_BYTES % 5, 0);
    assert_eq!(MAX_TOTAL_DECODED_BYTES, 1 << 18);
}

#[test]
fn production_sources_are_dependency_free_fixed_memory_and_profile_locked() {
    for source in [LIB, BASE32] {
        for forbidden in [
            "Vec<",
            "Vec::",
            "vec![",
            "String",
            "Box<",
            "Box::",
            "Rc<",
            "Arc<",
            "alloc::",
            "unsafe fn",
            "unsafe impl",
            "unsafe {",
            "std::fs",
            "std::io",
            "std::net",
            "std::env",
            "println!",
            "eprintln!",
            "thread::",
            "SystemTime",
            "getrandom",
            "OsRng",
            "rand::",
            "random(",
            "image::",
            "camera::",
            "ocr::",
            "qrcode::",
            "flate",
            "zlib",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden production token {forbidden}"
            );
        }
    }

    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert_eq!(LIB.matches("std::").count(), 1);
    assert!(LIB.contains("impl std::error::Error for BbqrError {}"));
    assert!(LIB.contains("output: &'a mut [u8; MAX_TOTAL_DECODED_BYTES],"));
    assert!(LIB.contains("received: [u64; 4],"));
    assert!(LIB.contains("pending_final: [u8; MAX_PART_DECODED_BYTES],"));
    assert!(BASE32.contains("const ALPHABET: &[u8; 32] = b\"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567\";"));
    assert!(!BASE32.contains("pub fn "));
    assert!(!BASE32.contains("pub struct "));
    assert!(!BASE32.contains("pub enum "));

    assert!(MANIFEST.contains("[dependencies]\n"));
    let dependency_tail = MANIFEST.split_once("[dependencies]\n").unwrap().1;
    assert!(
        dependency_tail.trim().is_empty(),
        "dependency section is empty"
    );
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("build ="));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("path ="));
}

#[test]
fn canonical_encoding_and_rejection_outputs_are_byte_stable() {
    let payload = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let expected: [&[u8]; 3] = [b"B$2P0300AAAQEAYE", b"B$2P0301AUDAOCAJ", b"B$2P0302BI"];

    for (part_index, expected_frame) in expected.iter().enumerate() {
        let mut frame = [0xa5; MAX_FRAME_TEXT_BYTES];
        let frame_len = qk_bbqr::encode_frame(&payload, 5, part_index as u16, &mut frame).unwrap();
        assert_eq!(&frame[..frame_len], *expected_frame);
        assert!(frame[frame_len..].iter().all(|byte| *byte == 0xa5));

        let mut decoded = [0x5a; MAX_PART_DECODED_BYTES];
        let metadata = qk_bbqr::decode_frame(&frame[..frame_len], &mut decoded).unwrap();
        let start = part_index * 5;
        let end = payload.len().min(start + 5);
        assert_eq!(metadata.declared_parts, 3);
        assert_eq!(usize::from(metadata.part_index), part_index);
        assert_eq!(metadata.decoded_len, end - start);
        assert_eq!(&decoded[..metadata.decoded_len], &payload[start..end]);
        assert!(decoded[metadata.decoded_len..]
            .iter()
            .all(|byte| *byte == 0x5a));
    }

    let mut frame = [0x3c; MAX_FRAME_TEXT_BYTES];
    let before_frame = frame;
    assert_eq!(
        qk_bbqr::encode_frame(&payload, 4, 0, &mut frame),
        Err(BbqrError::InvalidNonFinalPartLength)
    );
    assert_eq!(frame, before_frame);

    let mut decoded = [0xc3; MAX_PART_DECODED_BYTES];
    let before_decoded = decoded;
    assert_eq!(
        qk_bbqr::decode_frame(b"B$2P0100MZ", &mut decoded),
        Err(BbqrError::NonCanonicalBase32Padding)
    );
    assert_eq!(decoded, before_decoded);
}
