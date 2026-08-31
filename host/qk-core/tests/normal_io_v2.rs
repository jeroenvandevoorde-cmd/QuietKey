//! QK-DEC-149 profile/export surface and private-constructor locks.

use qk_core::{NormalArtifactErrorV2, NormalProfileV2};

const ARTIFACT_SOURCE: &str = include_str!("../src/normal_artifact_v2.rs");

#[test]
fn profile_parsing_has_no_default_and_route_exposure_is_exact() {
    assert_eq!(
        NormalProfileV2::parse(&[]),
        Err(NormalArtifactErrorV2::ProfileMissing)
    );
    assert_eq!(
        NormalProfileV2::parse(&[0]),
        Err(NormalArtifactErrorV2::ProfileUnknown)
    );
    assert_eq!(
        NormalProfileV2::parse(&[1, 2]),
        Err(NormalArtifactErrorV2::ProfileMalformed)
    );

    let simple = NormalProfileV2::parse(&[1]).expect("SimpleRecovery");
    let inheritance = NormalProfileV2::parse(&[2]).expect("Inheritance");
    let quantum = NormalProfileV2::parse(&[3]).expect("QuantumShelter");
    assert_eq!(simple.route_exposure(), inheritance.route_exposure());
    assert!(simple.route_exposure().sd_finalized_psbt());
    assert!(simple.route_exposure().sd_raw_transaction());
    assert!(simple.route_exposure().bbqr_finalized_psbt());
    assert!(!simple.route_exposure().bbqr_raw_transaction());
    assert!(!quantum.route_exposure().sd_finalized_psbt());
    assert!(quantum.route_exposure().sd_raw_transaction());
    assert!(!quantum.route_exposure().bbqr_finalized_psbt());
    assert!(quantum.route_exposure().bbqr_raw_transaction());
}

#[test]
fn artifact_bytes_have_only_a_crate_private_verified_finalization_entry() {
    for required in [
        "struct FinalizedArtifactViewV2<'a>",
        "fn from_finalized(finalized: &'a FinalizedNormalV3) -> Self",
        "pub(crate) fn bind_finalized(",
        "Self::bind_view(profile, FinalizedArtifactViewV2::from_finalized(finalized))",
        "struct NormalArtifactOwnerV2",
        "bytes: WipingVec,",
        "pub(crate) fn select(",
        "verify_bbqr_batch(artifact, non_final_part_len, frame_count, encoded_frames)?",
        "NormalArtifactErrorV2::PartialSdCompletion",
    ] {
        assert!(
            ARTIFACT_SOURCE.contains(required),
            "missing artifact ownership lock {required}"
        );
    }
    for forbidden in [
        "pub struct FinalizedArtifactViewV2",
        "pub fn bind_finalized",
        "pub(crate) fn bind_verified",
        "pub fn from_bytes",
        "pub fn new(finalized_psbt",
        "pub fn retry",
        "pub fn fallback",
    ] {
        assert!(
            !ARTIFACT_SOURCE.contains(forbidden),
            "arbitrary or retry surface escaped: {forbidden}"
        );
    }
}

#[test]
fn all_local_export_names_are_stable_and_non_hostile() {
    let cases = [
        (NormalArtifactErrorV2::ProfileMissing, "ProfileMissing"),
        (NormalArtifactErrorV2::ProfileUnknown, "ProfileUnknown"),
        (NormalArtifactErrorV2::ProfileMalformed, "ProfileMalformed"),
        (
            NormalArtifactErrorV2::InvalidTransition,
            "InvalidTransition",
        ),
        (
            NormalArtifactErrorV2::ExportRouteUnavailable,
            "ExportRouteUnavailable",
        ),
        (
            NormalArtifactErrorV2::ExportArtifactInvariant,
            "ExportArtifactInvariant",
        ),
        (
            NormalArtifactErrorV2::ExportReceiptMismatch,
            "ExportReceiptMismatch",
        ),
        (
            NormalArtifactErrorV2::BbqrVerificationMismatch,
            "BbqrVerificationMismatch",
        ),
        (
            NormalArtifactErrorV2::PartialSdCompletion,
            "PartialSdCompletion",
        ),
        (NormalArtifactErrorV2::Finished, "Finished"),
    ];
    for (error, name) in cases {
        assert_eq!(error.name(), name);
        assert_eq!(error.to_string(), name);
    }
}
