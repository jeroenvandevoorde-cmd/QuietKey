//! One-read staging, closed fault precedence, and cleanup source locks.

use qk_update::{
    stage_from_media, MockMediaCandidate, MockMediaFaults, MockReadOnlyMedia, UpdateError,
    UpdatePresence, MIN_PACKAGE_BYTES, UPDATE_FILE_NAME,
};

const STAGING_SOURCE: &str = include_str!("../src/staging.rs");
const WIPE_SOURCE: &str = include_str!("../src/wipe.rs");
const PACKAGE_SOURCE: &str = include_str!("../src/package.rs");

fn package_bytes() -> Vec<u8> {
    vec![0xa5; MIN_PACKAGE_BYTES]
}

fn rejection(media: &mut MockReadOnlyMedia, presence: UpdatePresence) -> UpdateError {
    match stage_from_media(media, presence) {
        Ok(_) => panic!("staging was expected to reject"),
        Err(error) => error,
    }
}

fn assert_consuming_rejection(mut media: MockReadOnlyMedia, expected: UpdateError) {
    assert_eq!(media.read_attempts(), 0);
    assert!(!media.consumed());
    assert_eq!(rejection(&mut media, UpdatePresence::clear()), expected);
    assert_eq!(media.read_attempts(), 1);
    assert!(media.consumed());
    assert_eq!(
        rejection(&mut media, UpdatePresence::clear()),
        UpdateError::MediaAlreadyRead
    );
    assert_eq!(media.read_attempts(), 1, "no second source read");
}

#[test]
fn success_consumes_the_media_once_and_exposes_only_length() {
    let mut media = MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(package_bytes())]);
    let staged = stage_from_media(&mut media, UpdatePresence::clear()).expect("first stage");
    assert_eq!(staged.byte_length(), MIN_PACKAGE_BYTES);
    assert!(media.consumed());
    assert_eq!(media.read_attempts(), 1);
    drop(staged);

    assert_eq!(
        rejection(&mut media, UpdatePresence::clear()),
        UpdateError::MediaAlreadyRead
    );
    assert_eq!(media.read_attempts(), 1);
}

#[test]
fn wallet_and_card_preconditions_precede_every_media_state() {
    let mut media = MockReadOnlyMedia::with_faults(Vec::new(), MockMediaFaults::read_failure());
    assert_eq!(
        rejection(&mut media, UpdatePresence::new(true, true)),
        UpdateError::WalletSessionActive,
        "wallet state precedes card state"
    );
    assert_eq!(media.read_attempts(), 0);
    assert!(!media.consumed());

    assert_eq!(
        rejection(&mut media, UpdatePresence::new(false, true)),
        UpdateError::CardPresent
    );
    assert_eq!(media.read_attempts(), 0);
    assert!(!media.consumed());

    assert_eq!(
        rejection(&mut media, UpdatePresence::clear()),
        UpdateError::MediaReadFailed
    );
    assert_eq!(media.read_attempts(), 1);
    assert!(media.consumed());

    assert_eq!(
        rejection(&mut media, UpdatePresence::new(true, true)),
        UpdateError::WalletSessionActive,
        "presence is checked again before consumed-media state"
    );
    assert_eq!(
        rejection(&mut media, UpdatePresence::new(false, true)),
        UpdateError::CardPresent
    );
    assert_eq!(
        rejection(&mut media, UpdatePresence::clear()),
        UpdateError::MediaAlreadyRead
    );
    assert_eq!(media.read_attempts(), 1);
}

#[test]
fn read_fault_precedes_candidate_selection_and_consumes_capability() {
    assert_consuming_rejection(
        MockReadOnlyMedia::with_faults(Vec::new(), MockMediaFaults::read_failure()),
        UpdateError::MediaReadFailed,
    );
    assert_consuming_rejection(
        MockReadOnlyMedia::with_faults(
            vec![
                MockMediaCandidate::new("wrong", Vec::new()),
                MockMediaCandidate::new("also-wrong", Vec::new()),
            ],
            MockMediaFaults::read_failure(),
        ),
        UpdateError::MediaReadFailed,
    );
}

#[test]
fn candidate_count_precedes_name_and_length() {
    assert_consuming_rejection(
        MockReadOnlyMedia::new(Vec::new()),
        UpdateError::UpdateCandidateMissing,
    );
    assert_consuming_rejection(
        MockReadOnlyMedia::new(vec![
            MockMediaCandidate::new("wrong-a", Vec::new()),
            MockMediaCandidate::new("wrong-b", Vec::new()),
        ]),
        UpdateError::SecondUpdateCandidate,
    );
    assert_consuming_rejection(
        MockReadOnlyMedia::new(vec![
            MockMediaCandidate::canonical(package_bytes()),
            MockMediaCandidate::new("unrelated", Vec::new()),
        ]),
        UpdateError::SecondUpdateCandidate,
    );
}

#[test]
fn root_filename_is_byte_exact_and_precedes_length_and_copy_faults() {
    for wrong in [
        "QuietKey-update.qkup",
        "quietkey-update.QKUP",
        "./quietkey-update.qkup",
        "sub/quietkey-update.qkup",
        "quietkey-update.qkup\0",
        "quietkey-update.qkup.bak",
    ] {
        assert_consuming_rejection(
            MockReadOnlyMedia::new(vec![MockMediaCandidate::new(wrong, Vec::new())]),
            UpdateError::UpdateCandidateMissing,
        );
    }

    assert_consuming_rejection(
        MockReadOnlyMedia::with_faults(
            vec![MockMediaCandidate::new("wrong", package_bytes())],
            MockMediaFaults::copy_failure_after(0),
        ),
        UpdateError::UpdateCandidateMissing,
    );
    assert_eq!(UPDATE_FILE_NAME.as_bytes(), b"quietkey-update.qkup");
}

#[test]
fn package_length_precedes_copy_fault_and_exact_minimum_is_accepted() {
    assert_consuming_rejection(
        MockReadOnlyMedia::with_faults(
            vec![MockMediaCandidate::canonical(vec![
                0xa5;
                MIN_PACKAGE_BYTES - 1
            ])],
            MockMediaFaults::copy_failure_after(0),
        ),
        UpdateError::PackageLengthOutOfBounds,
    );

    let mut media = MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(package_bytes())]);
    let staged = stage_from_media(&mut media, UpdatePresence::clear()).expect("minimum accepted");
    assert_eq!(staged.byte_length(), MIN_PACKAGE_BYTES);
    assert_eq!(media.read_attempts(), 1);
}

#[test]
fn every_reachable_copy_fault_boundary_is_named_and_one_read() {
    for byte_count in [
        0,
        1,
        MIN_PACKAGE_BYTES / 2,
        MIN_PACKAGE_BYTES - 1,
        MIN_PACKAGE_BYTES,
    ] {
        assert_consuming_rejection(
            MockReadOnlyMedia::with_faults(
                vec![MockMediaCandidate::canonical(package_bytes())],
                MockMediaFaults::copy_failure_after(byte_count),
            ),
            UpdateError::StagingCopyFailed,
        );
    }

    let mut media = MockReadOnlyMedia::with_faults(
        vec![MockMediaCandidate::canonical(package_bytes())],
        MockMediaFaults::copy_failure_after(MIN_PACKAGE_BYTES + 1),
    );
    let staged = stage_from_media(&mut media, UpdatePresence::clear())
        .expect("fault beyond exact copy is unreachable");
    assert_eq!(staged.byte_length(), MIN_PACKAGE_BYTES);
    assert!(media.consumed());
    assert_eq!(media.read_attempts(), 1);
}

#[test]
fn private_staging_and_verified_owners_expose_no_byte_accessor_or_copy_trait() {
    let staged = STAGING_SOURCE
        .split_once("pub struct StagedPackage {")
        .expect("staged owner")
        .1
        .split_once("/// Copy the sole canonical candidate")
        .expect("staged owner end")
        .0;
    for forbidden in [
        "#[derive(",
        "impl Clone for StagedPackage",
        "impl Copy for StagedPackage",
        "impl Debug for StagedPackage",
        "impl Display for StagedPackage",
        "pub fn bytes",
        "pub fn as_slice",
        "pub fn into_bytes",
    ] {
        assert!(!staged.contains(forbidden), "staged owner: {forbidden}");
    }
    assert!(staged.contains("bytes: WipingByteVec,"));
    assert!(staged.contains("pub fn byte_length(&self) -> usize"));
    assert!(staged.contains("pub(crate) fn bytes(&self) -> &[u8]"));

    let verified = PACKAGE_SOURCE
        .split_once("pub struct VerifiedPackage {")
        .expect("verified owner")
        .1
        .split_once("fn fixed<const N: usize>")
        .expect("verified owner end")
        .0;
    for forbidden in [
        "#[derive(",
        "impl Clone for VerifiedPackage",
        "impl Copy for VerifiedPackage",
        "impl Debug for VerifiedPackage",
        "impl Display for VerifiedPackage",
        "pub fn image_bytes",
        "pub fn package_bytes",
        "pub fn into_bytes",
    ] {
        assert!(!verified.contains(forbidden), "verified owner: {forbidden}");
    }
    assert!(verified.contains("staging: StagedPackage,"));
    assert!(verified.contains("pub(crate) fn image_bytes(&self)"));
}

#[test]
fn complete_allocation_wipe_and_drop_traits_are_source_locked() {
    let owner = WIPE_SOURCE
        .split_once("pub(crate) struct WipingByteVec {")
        .expect("wiping owner")
        .1;
    for forbidden in [
        "impl Clone for WipingByteVec",
        "impl Copy for WipingByteVec",
        "impl Debug for WipingByteVec",
        "impl Display for WipingByteVec",
        "pub struct WipingByteVec",
        "pub fn as_slice",
        "pub fn into_inner",
    ] {
        assert!(!owner.contains(forbidden), "wipe owner: {forbidden}");
    }
    for required in [
        "#[inline(never)]",
        "let capacity = value.capacity();",
        "allocation(value.as_mut_ptr(), capacity);",
        "unsafe { ptr::write_volatile(pointer.add(offset), 0) };",
        "compiler_fence(Ordering::SeqCst);",
        "impl Drop for WipingByteVec",
        "byte_vec(&mut self.value);",
    ] {
        assert!(WIPE_SOURCE.contains(required), "wipe route: {required}");
    }
    assert!(STAGING_SOURCE.contains("let mut staged = WipingByteVec::new();"));
    assert!(STAGING_SOURCE.contains("Ok(StagedPackage { bytes: staged })"));
    assert_eq!(
        WIPE_SOURCE.matches("impl Drop for WipingByteVec").count(),
        1
    );
    assert_eq!(
        WIPE_SOURCE
            .matches("ptr::write_volatile(pointer.add(offset), 0)")
            .count(),
        1
    );
}
