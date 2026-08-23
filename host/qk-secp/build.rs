//! Host-only build of the ratified libsecp256k1 product closure
//! (QK-DEC-041).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Compiles exactly `src/secp256k1.c`, `src/precomputed_ecmult.c`, and
//! `src/precomputed_ecmult_gen.c` from the vendored pinned tree, in
//! that order, with literal system `cc` and `ar` invoked directly (no
//! shell), the exact ratified flag list, and only the vendor include
//! and src include paths. Environment `CFLAGS` are never read or
//! injected. Outputs land only in `OUT_DIR`. The build fails closed
//! unless `HOST` equals `TARGET` and the target family is `unix`. No
//! network, configure, CMake, or autotools. No OD-01, reproducibility,
//! or target claim.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Ratified product compilation closure, in ratified order (QK-DEC-041).
const PRODUCT_UNITS: [&str; 3] = [
    "secp256k1.c",
    "precomputed_ecmult.c",
    "precomputed_ecmult_gen.c",
];

/// Exact ratified product flags (QK-DEC-041). Include paths are
/// appended separately as the only additions.
const PRODUCT_FLAGS: [&str; 22] = [
    "-std=c90",
    "-O2",
    "-fPIC",
    "-ffunction-sections",
    "-fdata-sections",
    "-fvisibility=hidden",
    "-DSECP256K1_NO_API_VISIBILITY_ATTRIBUTES=1",
    "-DECMULT_WINDOW_SIZE=15",
    "-DCOMB_BLOCKS=43",
    "-DCOMB_TEETH=6",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-pedantic",
    "-Wcast-align",
    "-Wnested-externs",
    "-Wno-long-long",
    "-Wno-overlength-strings",
    "-Wno-unused-function",
    "-Wshadow",
    "-Wstrict-prototypes",
    "-Wundef",
];

fn env_var(name: &str) -> String {
    match env::var(name) {
        Ok(v) => v,
        Err(_) => panic!("qk-secp build: required environment variable {name} is missing"),
    }
}

fn main() {
    // Fail closed: host-only build, never cross-compiled, unix family only.
    let host = env_var("HOST");
    let target = env_var("TARGET");
    if host != target {
        panic!("qk-secp build: HOST ({host}) != TARGET ({target}); cross builds are not ratified");
    }
    let family = env_var("CARGO_CFG_TARGET_FAMILY");
    if family != "unix" {
        panic!("qk-secp build: target family {family} is not unix; build is not ratified");
    }

    let out_dir = PathBuf::from(env_var("OUT_DIR"));
    let manifest_dir = PathBuf::from(env_var("CARGO_MANIFEST_DIR"));
    let vendor = manifest_dir
        .join("..")
        .join("..")
        .join("third_party")
        .join("libsecp256k1");
    let vendor = match vendor.canonicalize() {
        Ok(v) => v,
        Err(e) => panic!("qk-secp build: vendored libsecp256k1 tree not found: {e}"),
    };
    let include_dir = vendor.join("include");
    let src_dir = vendor.join("src");

    let mut objects: Vec<PathBuf> = Vec::new();
    for unit in PRODUCT_UNITS {
        let source = src_dir.join(unit);
        if !source.is_file() {
            panic!("qk-secp build: ratified unit {unit} is missing from the vendored tree");
        }
        let object = out_dir.join(format!("{unit}.o"));
        // Literal system cc, invoked directly without a shell; CFLAGS
        // are never read or injected.
        let status = Command::new("cc")
            .args(PRODUCT_FLAGS)
            .arg("-I")
            .arg(&include_dir)
            .arg("-I")
            .arg(&src_dir)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!("qk-secp build: cc failed on {unit} with status {s}"),
            Err(e) => panic!("qk-secp build: cc could not be invoked for {unit}: {e}"),
        }
        objects.push(object);
        println!("cargo:rerun-if-changed={}", source.display());
    }
    println!("cargo:rerun-if-changed={}", include_dir.display());
    // Watch the complete canonicalized vendor root: the compiled units
    // transitively consume headers under src/ (and include/), so any
    // vendored byte change must invalidate the native build rather
    // than leaving Cargo Fresh.
    println!("cargo:rerun-if-changed={}", vendor.display());

    // Literal system ar, archiving the ratified units in ratified order.
    let archive = out_dir.join("libqksecpvendored.a");
    let mut ar = Command::new("ar");
    ar.arg("crs").arg(&archive);
    for object in &objects {
        ar.arg(object);
    }
    match ar.status() {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("qk-secp build: ar failed with status {s}"),
        Err(e) => panic!("qk-secp build: ar could not be invoked: {e}"),
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=qksecpvendored");
}
