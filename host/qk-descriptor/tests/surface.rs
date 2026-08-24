//! Source and manifest restrictions for the frozen M11 public boundary.

const LIB: &str = include_str!("../src/lib.rs");
const DESCRIPTOR: &str = include_str!("../src/descriptor.rs");
const CHECKSUM: &str = include_str!("../src/checksum.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn public_exports_are_exact_and_pair_stays_opaque() {
    for required in [
        "DescriptorPair",
        "DerivedScript",
        "DescriptorParseError",
        "DescriptorDeriveError",
        "parse_descriptor_pair",
        "derive_receive_script",
        "derive_change_script",
    ] {
        assert!(LIB.contains(required), "{required}");
    }
    assert!(!LIB.contains("pub mod "));
    assert!(!DESCRIPTOR.contains("pub enum Branch"));
    assert!(!DESCRIPTOR.contains("pub fn checksum"));
    assert!(!DESCRIPTOR.contains("pub fn sha"));
    assert!(!DESCRIPTOR.contains("pub fn serialize"));
    assert!(!DESCRIPTOR.contains("pub fn normalize"));
    assert!(!DESCRIPTOR.contains("pub fn encode"));
    let pair_start = DESCRIPTOR.find("pub struct DescriptorPair").unwrap();
    let pair_end = DESCRIPTOR[pair_start..].find("\n}\n").unwrap() + pair_start;
    let pair_definition = &DESCRIPTOR[pair_start..pair_end];
    assert!(!pair_definition.contains("pub account"));
    assert!(!pair_definition.contains("pub wallet"));
    assert!(!DESCRIPTOR[..pair_start]
        .lines()
        .rev()
        .take(2)
        .any(|line| line.contains("derive(")));
    assert!(!DESCRIPTOR.contains("impl fmt::Debug for DescriptorPair"));
    assert!(!DESCRIPTOR.contains("impl fmt::Display for DescriptorPair"));
    assert!(!DESCRIPTOR.contains("impl Clone for DescriptorPair"));
    assert!(!DESCRIPTOR.contains("impl Copy for DescriptorPair"));
}

#[test]
fn production_sources_have_no_heap_unsafe_io_or_general_helpers() {
    let production_descriptor = DESCRIPTOR
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .unwrap();
    let production_checksum = CHECKSUM.split("\n#[cfg(test)]\nmod tests").next().unwrap();
    let production_sha = SHA256.split("\n#[cfg(test)]\nmod tests").next().unwrap();
    for source in [
        LIB,
        production_descriptor,
        production_checksum,
        production_sha,
    ] {
        for forbidden in [
            "Vec<",
            "Vec::",
            "String",
            "Box<",
            "Rc<",
            "Arc<",
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
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
    }
    assert!(!CHECKSUM.contains("checksum_generator"));
    assert!(!CHECKSUM.contains("generate_checksum"));
    assert!(!SHA256.contains("pub fn"));
    assert!(!CHECKSUM.contains("pub fn"));
}

#[test]
fn dependency_surface_is_one_unchanged_path_dependency() {
    assert!(MANIFEST
        .lines()
        .any(|line| line == "qk-bip32 = { path = \"../qk-bip32\" }"));
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("version = \"1"));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("qk-psbt"));
    assert!(!MANIFEST.contains("qk-secp"));
}
