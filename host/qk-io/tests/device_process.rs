#![cfg(feature = "host-runtime")]

//! Product-boundary source pins complement the behavioral unit tests kept
//! beside the private adapter implementation.

const DEVICE_PROCESS: &str = include_str!("../src/device_process.rs");
const PROCESS: &str = include_str!("../src/process.rs");

#[test]
fn device_descriptors_are_lazy_fixed_direction_and_have_no_reverse_output_path() {
    for exact in [
        "const CAMERA_INPUT_PATH: &str = \"/dev/fd/3\";",
        "const MEDIA_INPUT_PATH: &str = \"/dev/fd/4\";",
        "const PRINT_OUTPUT_PATH: &str = \"/dev/fd/5\";",
        "const MEDIA_OUTPUT_PATH: &str = \"/dev/fd/6\";",
        ".read(true)",
        ".write(true)",
    ] {
        assert!(
            DEVICE_PROCESS.contains(exact),
            "missing boundary pin {exact}"
        );
    }
    for forbidden in [
        ".read(true).write(true)",
        "MediaBeginAccepted",
        "MediaChunkAccepted",
        "MediaFinished",
        "MediaRejected",
        "SCM_RIGHTS",
        "UnixStream",
    ] {
        assert!(
            !DEVICE_PROCESS.contains(forbidden),
            "forbidden device bridge token {forbidden}"
        );
    }
}

#[test]
fn process_entry_keeps_legacy_boundaries_encapsulated_behind_the_device_owner() {
    assert!(PROCESS.contains("let mut devices = DeviceProcess::new();"));
    assert!(PROCESS.contains(".accept(&mut broker, &frame)"));
    assert!(!PROCESS.contains("MockInput"));
    assert!(!PROCESS.contains("MockOutputWriter"));
}

#[test]
fn bridge_retains_the_exact_one_use_and_cleanup_mechanisms() {
    for required in [
        "used_sources",
        "used_artifacts",
        "DeviceError::UnexpectedFrame",
        "WipingVec::try_zeroed",
        "WipingVec::try_from_slice",
        "crate::wipe::bytes(&mut scratch)",
        "crate::wipe::bytes(&mut finish)",
    ] {
        assert!(
            DEVICE_PROCESS.contains(required),
            "missing owner pin {required}"
        );
    }
}
