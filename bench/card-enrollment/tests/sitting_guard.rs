use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct GuardTree(PathBuf);

impl GuardTree {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "qk-sitting-guard-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let tree = Self(path);
        for relative in [
            "tools/check-bench-dependencies.sh",
            "bench/card-enrollment/Cargo.toml",
            "bench/card-enrollment/Cargo.lock",
            "bench/card-enrollment/DEPENDENCY-ALLOWLIST.tsv",
            "host/qk-card-model/Cargo.toml",
            "host/qk-card-protocol/Cargo.toml",
            "host/qk-secp/Cargo.toml",
        ] {
            tree.copy(root, relative);
        }
        for directory in ["src", "tests"] {
            let relative = format!("bench/card-enrollment/{directory}");
            for entry in fs::read_dir(root.join(&relative)).unwrap() {
                let entry = entry.unwrap();
                if entry.path().extension().is_some_and(|ext| ext == "rs") {
                    tree.copy(
                        root,
                        &format!("{relative}/{}", entry.file_name().to_str().unwrap()),
                    );
                }
            }
        }
        for name in ["sitting_install_v1.tsv", "sitting_provision_v1.tsv"] {
            tree.copy(
                root,
                &format!("bench/card-enrollment/tests/fixtures/{name}"),
            );
        }
        tree.git(&["init", "--quiet"]);
        tree.git(&["add", "."]);
        tree
    }

    fn copy(&self, root: &Path, relative: &str) {
        let target = self.0.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(root.join(relative), target).unwrap();
    }

    fn git(&self, args: &[&str]) {
        let result = Command::new("git")
            .args(args)
            .current_dir(&self.0)
            .output()
            .unwrap();
        assert!(result.status.success(), "git failed");
    }

    fn replace(&self, relative: &str, old: &str, new: &str) {
        let path = self.0.join(relative);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(old), "probe's original bytes absent");
        fs::write(path, text.replacen(old, new, 1)).unwrap();
    }

    fn run(&self) -> Output {
        Command::new("sh")
            .arg("tools/check-bench-dependencies.sh")
            .current_dir(&self.0)
            .env("CARGO_NET_OFFLINE", "true")
            .output()
            .unwrap()
    }

    fn rejects(&self, name: &str) {
        let output = self.run();
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            format!("FAIL: {name}")
        );
    }
}

impl Drop for GuardTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn reviewed_static_surface_reaches_the_closure_boundary() {
    // No host workspace is copied: this is the deliberate recursion barrier.
    GuardTree::new().rejects("host Cargo.lock generation failed offline");
}

#[test]
fn guard_rejects_model_moved_into_normal_dependencies() {
    let tree = GuardTree::new();
    tree.replace(
        "bench/card-enrollment/Cargo.toml",
        "[dev-dependencies]\n",
        "",
    );
    tree.rejects(
        "bench direct dependencies are not exactly pcsc 2.9.0 plus the two reviewed dev-only paths",
    );
}

#[test]
fn guard_rejects_changed_path_and_registry_allowlist_facts() {
    let tree = GuardTree::new();
    tree.replace("host/qk-card-model/Cargo.toml", "0.0.1", "0.0.2");
    tree.rejects("bench test path manifest checksum mismatch: host/qk-card-model/Cargo.toml");
    let tree = GuardTree::new();
    tree.replace(
        "bench/card-enrollment/DEPENDENCY-ALLOWLIST.tsv",
        "b588b76d",
        "0588b76d",
    );
    tree.rejects("bench dependency allowlist facts differ from QK-DEC-147");
}

#[test]
fn guard_rejects_alternate_path_syntax_and_registry_injection() {
    let tree = GuardTree::new();
    tree.replace(
        "bench/card-enrollment/Cargo.toml",
        "../../host/qk-card-model",
        "../../host/./qk-card-model",
    );
    tree.rejects(
        "bench direct dependencies are not exactly pcsc 2.9.0 plus the two reviewed dev-only paths",
    );
    let tree = GuardTree::new();
    tree.replace(
        "bench/card-enrollment/Cargo.toml",
        "[dependencies]\n",
        "[dependencies]\nother = \"1\"\n",
    );
    tree.rejects(
        "bench direct dependencies are not exactly pcsc 2.9.0 plus the two reviewed dev-only paths",
    );
}

#[test]
fn guard_rejects_unregistered_source_and_changed_lock() {
    let tree = GuardTree::new();
    fs::write(tree.0.join("bench/card-enrollment/src/unregistered.rs"), "").unwrap();
    tree.git(&["add", "bench/card-enrollment/src/unregistered.rs"]);
    tree.rejects("bench Rust source set is not exact");
    let tree = GuardTree::new();
    tree.replace("bench/card-enrollment/Cargo.lock", "b588b76d", "0588b76d");
    tree.rejects("bench Cargo.lock package set or checksum facts differ from QK-DEC-147");
}

#[test]
fn guard_rejects_changed_registered_sitting_bytes() {
    let tree = GuardTree::new();
    tree.replace(
        "bench/card-enrollment/tests/fixtures/sitting_install_v1.tsv",
        "00a4040006f0514b32420100",
        "00a4040006f0514b32420200",
    );
    tree.rejects("registered sitting fixture identity mismatch: bench/card-enrollment/tests/fixtures/sitting_install_v1.tsv");
}
