//! Frozen M18 public surface and fixed-memory source restrictions.

use qk_a1_codec::{decode, encode, CodecError, CodecProfile, DecodeReport};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const LIB: &str = include_str!("../src/lib.rs");
const BASE32: &str = include_str!("../src/base32.rs");
const GF256: &str = include_str!("../src/gf256.rs");
const REED_SOLOMON: &str = include_str!("../src/reed_solomon.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

const HEADER: [u8; 7] = [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01];
const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let counting = COUNTING.try_with(Cell::get).unwrap_or(false);
        if counting {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|counting| counting.set(true));
    let result = operation();
    COUNTING.with(|counting| counting.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    (result, allocations)
}

fn production_prefix(source: &str) -> &str {
    source.split("\n#[cfg(test)]\n").next().unwrap_or(source)
}

#[test]
fn public_surface_is_exactly_profiles_errors_report_and_two_operations() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub enum CodecProfile {",
            "pub enum CodecError {",
            "pub struct DecodeReport {",
            "pub corrected_errors: u8,",
            "pub erased_bytes: u8,",
            "pub fn encode(",
            "pub fn decode(",
        ],
        "complete public item and field surface"
    );

    for required in ["Rs72_60,", "Rs76_60,", "Rs80_60,"] {
        assert_eq!(LIB.matches(required).count(), 1, "profile {required}");
    }
    for required in [
        "InvalidCapsuleHeader,",
        "InvalidSymbolCount,",
        "MalformedErasureRepresentation,",
        "MalformedSymbol,",
        "NonCanonicalPadding,",
        "OverCapacity,",
        "NoUniqueCodeword,",
    ] {
        assert_eq!(LIB.matches(required).count(), 1, "error {required}");
    }

    for required in [
        "profile: CodecProfile,",
        "capsule: &[u8; CAPSULE_LEN],",
        "symbols_out: &mut [u8],",
        ") -> Result<(), CodecError>",
        "symbols: &[u8],",
        "erasure_mask: &[u8],",
        "capsule_out: &mut [u8; CAPSULE_LEN],",
        ") -> Result<DecodeReport, CodecError>",
    ] {
        assert!(LIB.contains(required), "signature pin {required}");
    }

    for forbidden in [
        "pub mod ",
        "pub const ",
        "pub use ",
        "impl Default for CodecProfile",
        "DEFAULT_PROFILE",
    ] {
        assert!(!LIB.contains(forbidden), "forbidden surface {forbidden}");
    }
    for source in [BASE32, GF256, REED_SOLOMON] {
        assert!(!source.contains("pub fn "), "no public primitive function");
        assert!(!source.contains("pub struct "), "no public primitive type");
        assert!(!source.contains("pub enum "), "no public primitive error");
    }
}

#[test]
fn geometry_alphabet_field_and_correction_pins_are_present() {
    for required in [
        "const FIXED_HEADER: [u8; 7] = [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01];",
        "const CAPSULE_LEN: usize = 67;",
        "const BODY_LEN: usize = 60;",
        "const MAX_CODEWORD_LEN: usize = 80;",
        "const MAX_SYMBOL_COUNT: usize = 128;",
        "Self::Rs72_60 => 12,",
        "Self::Rs76_60 => 16,",
        "Self::Rs80_60 => 20,",
        "Self::Rs72_60 => 116,",
        "Self::Rs76_60 => 122,",
        "Self::Rs80_60 => 128,",
    ] {
        assert!(LIB.contains(required), "geometry pin {required}");
    }
    assert!(BASE32.contains("const ALPHABET: &[u8; 32] = b\"23456789abcdefghijkmnpqrstuvwxyz\";"));
    assert!(BASE32.contains("let bit_index = symbol_index * 5 + symbol_bit;"));
    assert!(BASE32.contains("symbol_value & ((1u8 << padding_bits) - 1) != 0"));
    assert!(BASE32.contains("let first_byte = first_bit / 8;"));
    assert!(BASE32.contains("let last_byte = (first_bit + data_bits - 1) / 8;"));
    assert!(GF256.contains("const REDUCTION: u8 = 0x1d;"));
    assert!(GF256.contains("power(0x02, exponent % 255)"));
    assert!(REED_SOLOMON.contains("for (degree, root_index) in (0..parity).enumerate()"));
    assert!(REED_SOLOMON.contains("codeword_out[..DATA_LEN].copy_from_slice(data);"));
    assert!(REED_SOLOMON.contains("2 * error_degree + erasure_count > parity"));
    assert!(REED_SOLOMON.contains("Err(DecodeError::NoUniqueCodeword)"));
}

#[test]
fn production_sources_have_no_allocation_unsafe_io_randomness_or_adjacent_capability() {
    for source in [
        production_prefix(LIB),
        production_prefix(BASE32),
        production_prefix(GF256),
        production_prefix(REED_SOLOMON),
    ] {
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
            "std::",
            "unsafe fn",
            "unsafe impl",
            "unsafe {",
            "extern \"",
            "#[no_mangle]",
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
            "camera",
            "ocr::",
            "render(",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden production token {forbidden}"
            );
        }
    }

    for forbidden in [
        "use qk_a1",
        "qk_a1::",
        "A1Error",
        "pub fn authenticate",
        "pub fn decrypt",
        "pub fn encrypt",
        "pub fn checksum",
        "pub fn normalize",
        "pub fn render",
        "pub fn retry",
        "pub fn select_profile",
        "MAX_RETRIES",
        "DEFAULT_PROFILE",
    ] {
        assert!(!LIB.contains(forbidden), "excluded capability {forbidden}");
    }
}

#[test]
fn manifest_has_no_dependencies_or_build_surface() {
    assert!(MANIFEST.contains("[dependencies]\n"));
    let dependency_tail = MANIFEST.split_once("[dependencies]\n").unwrap().1;
    assert!(
        dependency_tail.trim().is_empty(),
        "dependency section is empty"
    );
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("build ="));
    assert!(!MANIFEST.contains("version = \"1"));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("path ="));
    assert!(!MANIFEST.contains("qk-a1 ="));
}

fn profile_geometry(profile: CodecProfile) -> (usize, usize, usize) {
    match profile {
        CodecProfile::Rs72_60 => (72, 12, 116),
        CodecProfile::Rs76_60 => (76, 16, 122),
        CodecProfile::Rs80_60 => (80, 20, 128),
    }
}

fn mark_unique_single_byte_erasures(codeword_len: usize, wanted: usize, mask: &mut [u8]) {
    let mut seen = [false; 80];
    let mut marked = 0usize;
    for (symbol_index, marker) in mask.iter_mut().enumerate() {
        let first_bit = symbol_index * 5;
        let data_bits = core::cmp::min(5, codeword_len * 8 - first_bit);
        let first_byte = first_bit / 8;
        let last_byte = (first_bit + data_bits - 1) / 8;
        if first_byte == last_byte && !seen[first_byte] {
            seen[first_byte] = true;
            *marker = 1;
            marked += 1;
            if marked == wanted {
                break;
            }
        }
    }
    assert_eq!(marked, wanted);
}

#[test]
fn public_encode_decode_and_rejection_paths_allocate_zero_bytes() {
    let mut capsule = [0u8; 67];
    capsule[..HEADER.len()].copy_from_slice(&HEADER);
    for (index, byte) in capsule[HEADER.len()..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
    }

    for profile in [
        CodecProfile::Rs72_60,
        CodecProfile::Rs76_60,
        CodecProfile::Rs80_60,
    ] {
        let (codeword_len, parity, symbol_count) = profile_geometry(profile);
        let mut symbols = [0u8; 128];
        let mut erasures = [0u8; 128];
        let mut output = [0u8; 67];

        let (result, allocations) =
            measured(|| encode(profile, &capsule, &mut symbols[..symbol_count]));
        assert_eq!(result, Ok(()));
        assert_eq!(allocations, 0);
        assert!(symbols[..symbol_count]
            .iter()
            .all(|symbol| ALPHABET.contains(symbol)));

        let (result, allocations) = measured(|| {
            decode(
                profile,
                &symbols[..symbol_count],
                &erasures[..symbol_count],
                &mut output,
            )
        });
        assert_eq!(
            result,
            Ok(DecodeReport {
                corrected_errors: 0,
                erased_bytes: 0,
            })
        );
        assert_eq!(allocations, 0);
        assert_eq!(output, capsule);

        let mut bad_header = capsule;
        bad_header[0] ^= 1;
        let (result, allocations) =
            measured(|| encode(profile, &bad_header, &mut symbols[..symbol_count]));
        assert_eq!(result, Err(CodecError::InvalidCapsuleHeader));
        assert_eq!(allocations, 0);

        let (result, allocations) =
            measured(|| encode(profile, &capsule, &mut symbols[..symbol_count - 1]));
        assert_eq!(result, Err(CodecError::InvalidSymbolCount));
        assert_eq!(allocations, 0);

        let (result, allocations) = measured(|| {
            decode(
                profile,
                &symbols[..symbol_count - 1],
                &erasures[..symbol_count - 1],
                &mut output,
            )
        });
        assert_eq!(result, Err(CodecError::InvalidSymbolCount));
        assert_eq!(allocations, 0);

        erasures[0] = 2;
        let (result, allocations) = measured(|| {
            decode(
                profile,
                &symbols[..symbol_count],
                &erasures[..symbol_count],
                &mut output,
            )
        });
        assert_eq!(result, Err(CodecError::MalformedErasureRepresentation));
        assert_eq!(allocations, 0);
        erasures[0] = 0;

        let saved_symbol = symbols[0];
        symbols[0] = 0xff;
        let (result, allocations) = measured(|| {
            decode(
                profile,
                &symbols[..symbol_count],
                &erasures[..symbol_count],
                &mut output,
            )
        });
        assert_eq!(result, Err(CodecError::MalformedSymbol));
        assert_eq!(allocations, 0);
        symbols[0] = saved_symbol;

        if symbol_count != 128 {
            let saved_final = symbols[symbol_count - 1];
            symbols[symbol_count - 1] = ALPHABET[1];
            let (result, allocations) = measured(|| {
                decode(
                    profile,
                    &symbols[..symbol_count],
                    &erasures[..symbol_count],
                    &mut output,
                )
            });
            assert_eq!(result, Err(CodecError::NonCanonicalPadding));
            assert_eq!(allocations, 0);
            symbols[symbol_count - 1] = saved_final;
        }

        mark_unique_single_byte_erasures(codeword_len, parity + 1, &mut erasures[..symbol_count]);
        let (result, allocations) = measured(|| {
            decode(
                profile,
                &symbols[..symbol_count],
                &erasures[..symbol_count],
                &mut output,
            )
        });
        assert_eq!(result, Err(CodecError::OverCapacity));
        assert_eq!(allocations, 0);
    }
}
