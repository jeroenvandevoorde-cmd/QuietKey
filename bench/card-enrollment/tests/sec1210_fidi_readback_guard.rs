use qk_card_enrollment::*;
use std::fs;
use std::os::unix::fs::symlink;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
const UTC: &str = "2026-09-12T00:00:00Z";
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "qk-t1-fidi-readback-guard-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> PathBuf {
        self.0.join(sec1210_fidi_readback_output_basename(UTC))
    }
    fn metadata(&self) -> Sec1210FidiReadbackMetadata {
        Sec1210FidiReadbackMetadata::new(
            "a".repeat(40),
            UTC.into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            self.path(),
        )
        .unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
#[test]
fn source_apparatus_specimen_calendar_and_output_are_precontact_gates() {
    let r = Root::new();
    for (source, utc, host, card, path) in [
        (
            "A".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.path(),
        ),
        (
            "a".repeat(39),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.path(),
        ),
        (
            "a".repeat(40),
            "2026-02-29T00:00:00Z",
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.path(),
        ),
        ("a".repeat(40), UTC, "iMac", "J3R180-03", r.path()),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-02",
            r.path(),
        ),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-01",
            r.path(),
        ),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            PathBuf::from(sec1210_fidi_readback_output_basename(UTC)),
        ),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.0.join(sec1210_output_basename(UTC)),
        ),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.0.join(sec1210_readback_output_basename(UTC)),
        ),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.0.join(sec1210_ifs_readback_output_basename(UTC)),
        ),
        (
            "a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            r.0.join("../")
                .join(sec1210_fidi_readback_output_basename(UTC)),
        ),
    ] {
        assert!(Sec1210FidiReadbackMetadata::new(source, utc.into(), host, card, path).is_err());
    }
    assert_eq!(r.metadata().output(), r.path());
    assert_eq!(fs::read_dir(&r.0).unwrap().count(), 0);
}
#[test]
fn existing_and_symlink_outputs_refuse_before_any_platform_action() {
    let r = Root::new();
    fs::write(r.path(), b"retained").unwrap();
    assert_eq!(
        execute_sec1210_fidi_readback(r.metadata())
            .unwrap_err()
            .name(),
        "Sec1210OutputCreateFailed"
    );
    assert_eq!(fs::read(r.path()).unwrap(), b"retained");
    let other = Root::new();
    symlink(r.path(), other.path()).unwrap();
    assert_eq!(
        execute_sec1210_fidi_readback(other.metadata())
            .unwrap_err()
            .name(),
        "Sec1210OutputCreateFailed"
    );
}
#[test]
#[cfg(not(target_os = "linux"))]
fn non_linux_fails_closed_with_private_failure_evidence() {
    let r = Root::new();
    let s = execute_sec1210_fidi_readback(r.metadata()).unwrap();
    assert_eq!(s.failure.unwrap().name(), "Sec1210UnsupportedPlatform");
    assert_eq!(s.request_count, 0);
    assert_eq!(
        fs::metadata(r.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(fs::read_to_string(r.path())
        .unwrap()
        .contains("result=Sec1210UnsupportedPlatform"));
}
#[test]
fn old_versions_plan_identity_and_single_uart_write_site_stay_pinned() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.0.12");
    assert_eq!(SEC1210_FIDI_READBACK_TOOL_VERSION, "0.0.12");
    assert_eq!(SEC1210_IFS_READBACK_TOOL_VERSION, "0.0.11");
    assert_eq!(SEC1210_READBACK_TOOL_VERSION, "0.0.10");
    assert_eq!(SEC1210_TOOL_VERSION, "0.0.9");
    assert_eq!(B6_TOOL_VERSION, "0.0.7");
    assert_eq!(
        READBACK_PLAN_SHA256,
        "6cedbdc6f53c8100e042b8d3e06ebef2a2c56b42e98bbfa32b3a951f39084c36"
    );
    let uart = include_str!("../src/uart_adapter.rs");
    assert_eq!(uart.matches(".write(request)").count(), 1);
    for forbidden in [
        "PowerOff",
        "SetParameters",
        "Escape",
        "pinctrl",
        "libc::",
        "serialport",
        "use nix::",
    ] {
        assert!(!uart.contains(forbidden));
    }
    assert_eq!(SEC1210_STTY_ARGS[8], "cstopb");
}

#[test]
fn cli_rejects_extra_caller_bytes_and_wrong_binding_before_output() {
    let root = Root::new();
    let output = root.path();
    for (specimen, extra) in [("J3R180-03", true), ("J3R180-01", false)] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_qk-card-enrollment"));
        command.args([
            "sec1210-fidi-readback",
            &"a".repeat(40),
            UTC,
            "RIG-HOST-PI3B-01",
            specimen,
            output.to_str().unwrap(),
        ]);
        if extra {
            command.arg("1810ff4d00fe00");
        }
        let report = command.output().unwrap();
        assert_eq!(report.status.code(), Some(64));
        assert!(!output.exists());
        assert!(report.stdout.is_empty());
    }
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}
