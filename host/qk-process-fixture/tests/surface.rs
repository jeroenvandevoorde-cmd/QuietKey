use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(path: &str) -> String {
    fs::read_to_string(root().join(path)).expect("registered source")
}

#[test]
fn fixture_workspace_is_ring_fenced_and_dependency_free_beyond_approved_leaves() {
    let manifest = source("Cargo.toml");
    assert!(manifest.contains("qk-bbqr = { path = \"../qk-bbqr\" }"));
    assert!(manifest.contains("qk-device-wire = { path = \"../qk-device-wire\" }"));
    assert!(!manifest.contains("qk-core"));
    assert!(!manifest.contains("qk-host-sim"));
    assert!(!manifest.contains("crates.io"));
}

#[test]
fn only_driver_includes_frozen_fixture_paths() {
    let common = source("src/main.rs");
    let driver = source("src/scenario.rs");
    assert!(!common.contains("include_str!"));
    assert!(driver.contains("../../qk-provisioning/tests/fixtures/provisioning_v2.txt"));
    assert!(driver.contains("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt"));
    assert!(driver.contains("PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL"));
}

#[test]
fn harness_locks_timeout_tree_kill_reap_and_exact_matrix() {
    let common = source("src/main.rs");
    let harness = source("src/bin/qk-normal-process-harness.rs");
    assert!(common.contains("EXPECTED_SUCCESS_CYCLES: usize = 12"));
    assert!(common.contains("EXPECTED_NEGATIVE_CYCLES: usize = 7"));
    assert!(harness.contains("kill_group(group)"));
    assert!(harness.contains("supervisor.wait()"));
    assert!(harness.contains("driver.wait()"));
    assert!(harness.contains("CYCLE_TIMEOUT_MILLIS"));
    for case in [
        "hostile-qkdv",
        "ingress-cap",
        "profile-mismatch",
        "early-hold",
        "wrong-wallet",
        "wrong-key",
        "high-s",
    ] {
        assert!(common.contains(case));
    }
}

#[test]
fn exact_supervisor_and_driver_descriptor_topologies_are_source_pinned() {
    let harness = source("src/bin/qk-normal-process-harness.rs");
    for mapping in [
        ".write.as_raw_fd(), 7",
        ".read.as_raw_fd(), 8",
        ".read.as_raw_fd(), 9",
        ".write.as_raw_fd(), 10",
        ".read.as_raw_fd(), 11",
        ".read.as_raw_fd(), 12",
        ".write.as_raw_fd(), 13",
        ".write.as_raw_fd(), 14",
    ] {
        assert!(harness.contains(mapping), "missing {mapping}");
    }
    assert!(harness.contains("ProcessGroup::Leader"));
    assert!(harness.contains("ProcessGroup::Join(group)"));
}
