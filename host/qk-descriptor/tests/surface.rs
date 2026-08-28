//! Source and manifest restrictions for the parallel v1/v2 descriptor boundary.

const LIB: &str = include_str!("../src/lib.rs");
const DESCRIPTOR: &str = include_str!("../src/descriptor.rs");
const CHECKSUM: &str = include_str!("../src/checksum.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

fn public_exports() -> Vec<&'static str> {
    LIB.split("pub use descriptor::{")
        .nth(1)
        .expect("descriptor export block")
        .split("};")
        .next()
        .expect("descriptor export terminator")
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

fn struct_definition(name: &str) -> &'static str {
    let marker = format!("pub struct {name} {{");
    let start = DESCRIPTOR.find(&marker).expect("public struct");
    let tail = &DESCRIPTOR[start..];
    let end = tail.find("\n}\n").expect("struct terminator") + 2;
    &tail[..end]
}

fn function_definition(name: &str) -> &'static str {
    let marker = format!("pub fn {name}(");
    let start = DESCRIPTOR.find(&marker).expect("public function");
    let tail = &DESCRIPTOR[start..];
    let end = tail.find("\n}\n").expect("function terminator") + 2;
    &tail[..end]
}

#[test]
fn public_exports_are_exact_parallel_v1_and_v2_surfaces() {
    assert_eq!(
        public_exports(),
        [
            "derive_change_script",
            "derive_change_script_v2",
            "derive_receive_script",
            "derive_receive_script_v2",
            "match_change_derivation_claims",
            "match_change_derivation_claims_v2",
            "match_receive_derivation_claims",
            "match_receive_derivation_claims_v2",
            "parse_descriptor_pair",
            "parse_descriptor_pair_v2",
            "DerivedScript",
            "DerivedScriptV2",
            "DescriptorDeriveError",
            "DescriptorPair",
            "DescriptorPairV2",
            "DescriptorParseError",
        ]
    );
    assert_eq!(
        LIB.lines()
            .filter(|line| line.trim_start().starts_with("pub "))
            .collect::<Vec<_>>(),
        ["pub use descriptor::{"]
    );
    assert!(!LIB.contains("pub mod "));
    assert!(LIB.contains("The unsuffixed surface preserves the frozen v1 three-account profile."));
    assert!(LIB.contains("The explicitly suffixed v2 surface accepts only the two-account"));
}

#[test]
fn both_pair_types_are_opaque_and_non_trait_bearing() {
    for name in ["DescriptorPair", "DescriptorPairV2"] {
        let marker = format!("pub struct {name} {{");
        let start = DESCRIPTOR.find(&marker).expect("pair struct");
        let definition = struct_definition(name);
        assert!(!definition
            .lines()
            .skip(1)
            .any(|line| line.trim_start().starts_with("pub ")));
        let item_attributes = DESCRIPTOR[..start]
            .rsplit("\n\n")
            .next()
            .expect("pair item attributes");
        assert!(!item_attributes.contains("#[derive"));
        for trait_name in ["fmt::Debug", "fmt::Display", "Clone", "Copy"] {
            assert!(
                !DESCRIPTOR.contains(&format!("impl {trait_name} for {name}")),
                "{name} implements {trait_name}"
            );
        }
    }

    assert!(
        DESCRIPTOR.contains("pub const fn origin_fingerprints(&self) -> [[u8; 4]; ACCOUNT_COUNT]")
    );
    assert!(DESCRIPTOR
        .contains("pub const fn origin_fingerprints(&self) -> [[u8; 4]; V2_ACCOUNT_COUNT]"));
    assert_eq!(
        DESCRIPTOR
            .matches("pub fn wallet_id(&self) -> [u8; 32]")
            .count(),
        2
    );
}

#[test]
fn v2_shape_is_fixed_and_profile_dispatch_is_impossible() {
    let v1_derived = struct_definition("DerivedScript");
    let v2_derived = struct_definition("DerivedScriptV2");
    assert!(v1_derived.contains("pub witness_script: [u8; WITNESS_SCRIPT_LEN]"));
    assert!(v1_derived.contains("pub script_pubkey: [u8; SCRIPT_PUBKEY_LEN]"));
    assert!(v2_derived.contains("pub witness_script: [u8; V2_WITNESS_SCRIPT_LEN]"));
    assert!(v2_derived.contains("pub script_pubkey: [u8; V2_SCRIPT_PUBKEY_LEN]"));

    for identity in [
        "const DESCRIPTOR_LEN: usize = 445;",
        "const ACCOUNT_COUNT: usize = 3;",
        "const WITNESS_SCRIPT_LEN: usize = 105;",
        "const WALLET_TRANSCRIPT_LEN: usize = 891;",
        "const V2_DESCRIPTOR_LEN: usize = 306;",
        "const V2_ACCOUNT_COUNT: usize = 2;",
        "const V2_WITNESS_SCRIPT_LEN: usize = 71;",
        "const V2_WALLET_TRANSCRIPT_LEN: usize = 613;",
        "const _: () = assert!(V2_DESCRIPTOR_LEN == V2_BODY_LEN + 1 + CHECKSUM_LEN);",
        "const _: () = assert!(V2_WALLET_TRANSCRIPT_LEN == V2_DESCRIPTOR_LEN * 2 + 1);",
        "const _: () = assert!(V2_WITNESS_SCRIPT_LEN == 1 + V2_ACCOUNT_COUNT * 34 + 2);",
    ] {
        assert!(DESCRIPTOR.contains(identity), "{identity}");
    }

    let v1_parser = function_definition("parse_descriptor_pair");
    assert!(v1_parser.contains("Result<DescriptorPair, DescriptorParseError>"));
    assert!(v1_parser.contains("parse_with_decoder(receive, change, decode_mainnet_xpub)"));
    assert!(!v1_parser.contains("V2_"));
    assert!(!v1_parser.contains("_v2"));

    let v2_parser = function_definition("parse_descriptor_pair_v2");
    assert!(v2_parser.contains("Result<DescriptorPairV2, DescriptorParseError>"));
    assert!(v2_parser.contains("parse_with_decoder_v2(receive, change, decode_mainnet_xpub)"));
    assert_eq!(
        DESCRIPTOR.matches("pub fn parse_descriptor_pair(").count(),
        1
    );
    assert_eq!(
        DESCRIPTOR
            .matches("pub fn parse_descriptor_pair_v2(")
            .count(),
        1
    );
    assert!(!DESCRIPTOR.contains("pub enum Profile"));
    assert!(!DESCRIPTOR.contains("pub fn parse_auto"));
    assert!(!DESCRIPTOR.contains("pub fn parse_any"));
    assert!(!DESCRIPTOR.contains("match receive.len()"));
    assert!(!DESCRIPTOR.contains("if receive.len() == V2_DESCRIPTOR_LEN"));

    for name in [
        "derive_receive_script",
        "derive_change_script",
        "match_receive_derivation_claims",
        "match_change_derivation_claims",
    ] {
        let function = function_definition(name);
        assert!(function.contains("pair: &DescriptorPair,"), "{name}");
        assert!(!function.contains("DescriptorPairV2"), "{name}");
        assert!(!function.contains("DerivedScriptV2"), "{name}");
        assert!(!function.contains("V2_ACCOUNT_COUNT"), "{name}");
    }
    for name in [
        "derive_receive_script_v2",
        "derive_change_script_v2",
        "match_receive_derivation_claims_v2",
        "match_change_derivation_claims_v2",
    ] {
        let function = function_definition(name);
        assert!(function.contains("pair: &DescriptorPairV2,"), "{name}");
        assert!(function.contains("DerivedScriptV2"), "{name}");
    }

    assert!(DESCRIPTOR.contains(
        "pair: &DescriptorPairV2,\n    index: u32,\n) -> Result<DerivedScriptV2, DescriptorDeriveError>"
    ));
    assert!(DESCRIPTOR.contains("claimed_role_keys: &[Option<[u8; 33]>; V2_ACCOUNT_COUNT]"));
    assert!(DESCRIPTOR.contains("witness_script[V2_WITNESS_SCRIPT_LEN - 2] = 0x52;"));
    assert!(DESCRIPTOR.contains("witness_script[V2_WITNESS_SCRIPT_LEN - 1] = 0xae;"));
}

#[test]
fn production_sources_have_no_heap_unsafe_io_or_general_helpers() {
    let production_descriptor = DESCRIPTOR
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("production descriptor source");
    let production_checksum = CHECKSUM
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("production checksum source");
    let production_sha = SHA256
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("production sha source");
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
            "HashMap",
            "BTreeMap",
            "alloc::",
            "unsafe fn",
            "unsafe impl",
            "unsafe {",
            "std::fs",
            "std::io",
            "std::net",
            "std::env",
            "std::process",
            "println!",
            "eprintln!",
            "thread::",
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
    }

    for forbidden in [
        "pub enum Branch",
        "pub enum Profile",
        "pub fn checksum",
        "pub fn sha",
        "pub fn serialize",
        "pub fn normalize",
        "pub fn encode",
        "pub fn decode",
        "pub fn derive(",
        "pub fn account",
        "pub fn xpub",
    ] {
        assert!(!DESCRIPTOR.contains(forbidden), "{forbidden}");
    }
    assert!(!CHECKSUM.contains("checksum_generator"));
    assert!(!CHECKSUM.contains("generate_checksum"));
    assert!(!SHA256.contains("pub fn"));
    assert!(!CHECKSUM.contains("pub fn"));
}

#[test]
fn dependency_surface_is_exactly_one_path_dependency_with_current_description() {
    let dependency_section = MANIFEST
        .split("[dependencies]\n")
        .nth(1)
        .expect("dependency section");
    let dependency_lines: Vec<_> = dependency_section
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(dependency_lines, ["qk-bip32 = { path = \"../qk-bip32\" }"]);
    assert_eq!(
        MANIFEST
            .lines()
            .filter(|line| line.starts_with("qk-bip32 ="))
            .count(),
        1
    );
    assert_eq!(MANIFEST.matches("../qk-bip32").count(), 1);
    assert_eq!(MANIFEST.matches("[dependencies]").count(), 1);
    assert_eq!(
        MANIFEST
            .lines()
            .filter(|line| line.trim_start().starts_with("version ="))
            .collect::<Vec<_>>(),
        ["version = \"0.0.1\""]
    );
    assert!(MANIFEST.contains("edition = \"2021\""));
    assert!(MANIFEST.contains("publish = false"));
    assert!(MANIFEST.contains(
        "description = \"Strict HOST-only paired mainnet descriptor parsing, wallet-id hashing, and bounded public P2WSH derivation for frozen v1 2-of-3 migration residue and v2 2-of-2. Not a wallet, ownership proof, or product.\""
    ));
    for forbidden in [
        "[dev-dependencies]",
        "[build-dependencies]",
        "git =",
        "registry =",
        "workspace =",
        "qk-psbt",
        "qk-secp",
    ] {
        assert!(!MANIFEST.contains(forbidden), "{forbidden}");
    }
}
