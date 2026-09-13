use qk_card_enrollment::{
    execute_sec1210_probe, sec1210_output_basename, Sec1210Error as E, Sec1210Metadata,
    SEC1210_STTY_ARGS, SEC1210_TOOL_VERSION,
};
use std::fs;
use std::os::unix::fs::symlink;
#[cfg(not(target_os = "linux"))]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qk-sec1210-guard-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn output(&self) -> PathBuf {
        self.0.join(sec1210_output_basename("2026-09-11T00:00:00Z"))
    }
    fn metadata(&self) -> Sec1210Metadata {
        Sec1210Metadata::new(
            "a".repeat(40),
            "2026-09-11T00:00:00Z".into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            self.output(),
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
fn metadata_pins_only_registered_apparatus_specimen_and_new_basename() {
    let root = Root::new();
    for host in ["iMac", "RIG-HOST-PI3B-02", "RIG-HOST-PI3B-01\n"] {
        assert!(Sec1210Metadata::new(
            "a".repeat(40),
            "2026-09-11T00:00:00Z".into(),
            host,
            "J3R180-03",
            root.output()
        )
        .is_err());
    }
    for specimen in ["J3R180-01", "J3R180-02", "J3R180-04"] {
        assert!(Sec1210Metadata::new(
            "a".repeat(40),
            "2026-09-11T00:00:00Z".into(),
            "RIG-HOST-PI3B-01",
            specimen,
            root.output()
        )
        .is_err());
    }
    for path in [
        PathBuf::from("relative.txt"),
        root.0.join("wrong.txt"),
        root.0.join("../").join(root.output().file_name().unwrap()),
    ] {
        assert!(Sec1210Metadata::new(
            "a".repeat(40),
            "2026-09-11T00:00:00Z".into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            path
        )
        .is_err());
    }
}
#[test]
fn source_and_calendar_validation_refuse_injection_before_contact() {
    let root = Root::new();
    for source in [
        "a".repeat(39),
        "A".repeat(40),
        format!("{}\n", "a".repeat(39)),
    ] {
        assert!(Sec1210Metadata::new(
            source,
            "2026-09-11T00:00:00Z".into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            root.output()
        )
        .is_err());
    }
    for utc in [
        "2026-02-29T00:00:00Z",
        "2026-09-31T00:00:00Z",
        "2026-09-11T24:00:00Z",
        "2026-09-11T00:00:60Z",
        "2026-09-11T00:00:00Z\n",
    ] {
        assert!(Sec1210Metadata::new(
            "a".repeat(40),
            utc.into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            root.output()
        )
        .is_err());
    }
}
#[test]
fn existing_output_and_symlink_refuse_before_device_access() {
    let root = Root::new();
    fs::write(root.output(), b"retained").unwrap();
    assert_eq!(
        execute_sec1210_probe(root.metadata()),
        Err(E::OutputCreateFailed)
    );
    assert_eq!(fs::read(root.output()).unwrap(), b"retained");
    fs::remove_file(root.output()).unwrap();
    let target = root.0.join("target");
    fs::write(&target, b"retained").unwrap();
    symlink(&target, root.output()).unwrap();
    assert_eq!(
        execute_sec1210_probe(root.metadata()),
        Err(E::OutputCreateFailed)
    );
    assert_eq!(fs::read(target).unwrap(), b"retained");
}
#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_creates_private_refusal_without_device_access() {
    let root = Root::new();
    let summary = execute_sec1210_probe(root.metadata()).unwrap();
    assert_eq!(summary.failure, Some(E::UnsupportedPlatform));
    assert_eq!(summary.request_count, 0);
    assert_eq!(
        fs::metadata(root.output()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(root.output()).unwrap();
    assert!(text.contains("result=Sec1210UnsupportedPlatform"));
}
#[test]
fn serial_vector_and_lane_version_are_exact_no_fallback() {
    assert_eq!(SEC1210_STTY_ARGS.join(" "),"-F /dev/ttyAMA0 115200 raw -echo -echonl cs8 -parenb cstopb cread clocal -hupcl -crtscts -parmrk -ignpar -inpck min 0 time 5");
    assert_eq!(SEC1210_TOOL_VERSION, "0.0.9");
    assert!(include_str!("../Cargo.toml").contains("version = \"0.0.11\""));
    assert!(include_str!("../src/b6.rs").contains("B6_TOOL_VERSION: &str = \"0.0.7\""));
}
#[test]
fn native_write_is_private_and_source_has_no_added_command_path() {
    let uart = include_str!("../src/uart_adapter.rs");
    let engine = include_str!("../src/sec1210.rs");
    assert!(uart.contains(".custom_flags(0x100)"));
    assert!(uart.contains(".create_new(true)"));
    assert_eq!(uart.matches(".write(request)").count(), 1);
    assert!(!uart.contains("pub struct"));
    for source in [uart, engine, include_str!("../src/sec1210_transcript.rs")] {
        for forbidden in [
            ".transmit(",
            "PowerOff",
            "XfrBlock",
            "INITIALIZE_UPDATE",
            "secret_key_import",
            "ecdsa_sign_rfc6979",
        ] {
            assert!(!source.contains(forbidden));
        }
    }
    for forbidden in ["libc", "nix", "serialport"] {
        assert!(!include_str!("../Cargo.toml").contains(forbidden));
    }
}
