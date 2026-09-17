//! QK-DEC-172 deterministic integrated owner qualification, with no device.
#![cfg(all(feature = "sec1210-production", feature = "normal-process"))]

#[path = "support/normal_signing_fixture.rs"]
mod fixture;

use fixture::{approval, Fault, Owner, SignFault, Trace};
use qk_core::{
    NormalProcessEventV2, NormalProcessStageV2, NormalSec1210DisplayV2, NormalSec1210ErrorV2,
    NormalStageV2, Sec1210ClockErrorV2, QK_LIM_APDU_021_MAX_SIGN_EXCHANGES,
};

fn assert_absorbed(owner: &mut Owner, trace: &Trace, error: NormalSec1210ErrorV2, unknown: bool) {
    assert_eq!(owner.terminal_error(), Some(error));
    assert_eq!(owner.stage(), NormalProcessStageV2::Terminated);
    assert!(owner.screen().is_none());
    assert!(trace.descriptor_dropped());
    let before = trace.writes();
    assert_eq!(
        owner
            .handle_event(NormalProcessEventV2::HoldCompleted)
            .err(),
        Some(error)
    );
    assert_eq!(owner.advance_automatic().err(), Some(error));
    assert_eq!(
        owner
            .handle_event(NormalProcessEventV2::SelectSd {
                caller_nonce: [1; 16]
            })
            .err(),
        Some(error)
    );
    let mut late = fixture::hex(fixture::field(fixture::SIGNING, "role_b_der_hex"));
    assert_eq!(owner.reject_card_reply(&mut late), error);
    assert!(late.iter().all(|byte| *byte == 0));
    if let Some(mut late) = trace.last_valid_sign_reply() {
        assert!(matches!(
            qk_card_protocol::parse_response(qk_card_protocol::Instruction::SignDigest, &late),
            Ok(qk_card_protocol::ResponseRef::SignDigest { .. })
        ));
        assert_eq!(owner.reject_card_reply(&mut late), error);
        assert!(late.iter().all(|byte| *byte == 0));
    }
    let mut qkip = vec![0x55; 20];
    assert_eq!(owner.receive_qkip(&mut qkip, false).err(), Some(error));
    assert_eq!(qkip, vec![0; 20]);
    assert_eq!(
        trace.writes(),
        before,
        "no retry, rebind or late reply dispatch"
    );
    let mut display_sink = Vec::new();
    while let Some(fact) = owner.take_display_fact() {
        display_sink.push(fact);
    }
    assert_eq!(
        display_sink.contains(&NormalSec1210DisplayV2::CardOutcomeUnknown),
        unknown
    );
    if unknown {
        assert_eq!(display_sink.last().and_then(|fact| fact.message()), Some(
            "Signing was not completed by this terminal. The card may have produced a signature before the failure."));
    }
    assert!(owner.take_display_fact().is_none());
}

#[test]
fn all_profiles_use_the_existing_signing_owner_and_frozen_binding_trace() {
    for profile in 1..=3 {
        let (mut owner, _broker, trace) = approval(profile, &fixture::psbt());
        assert!(owner
            .handle_event(NormalProcessEventV2::HoldCompleted)
            .expect("verified bound outcome")
            .is_none());
        assert_eq!(
            owner.stage(),
            NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction)
        );
        assert_eq!(owner.sign_attempts(), 1);
        assert_eq!(trace.sign_count(), 1);
        let apdus = trace.apdus();
        let instructions: Vec<u8> = apdus.iter().map(|apdu| apdu[1]).collect();
        assert_eq!(
            instructions,
            [0xa4, 0x10, 0x11, 0x12, 0x12, 0x12, 0x12, 0x13, 0x15]
        );
        assert_eq!(trace.writes().len(), 14);
        let mut stages = Vec::new();
        while let Some(fact) = owner.take_display_fact() {
            stages.push(fact);
        }
        assert!(stages.contains(&NormalSec1210DisplayV2::Stage(NormalStageV2::CardBSigning)));
        assert!(!stages.contains(&NormalSec1210DisplayV2::CardOutcomeUnknown));
        drop(owner);
        assert!(trace.descriptor_dropped());
    }
}

#[test]
fn zero_wtx_full_envelope_is_eight_binding_plus_one_hundred_signs() {
    assert_eq!(QK_LIM_APDU_021_MAX_SIGN_EXCHANGES, 100);
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt_with_inputs(100));
    owner
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("complete100");
    assert_eq!(owner.sign_attempts(), 100);
    assert_eq!(trace.sign_count(), 100);
    assert_eq!(trace.apdus().len(), 108);
    assert_eq!(
        trace.writes().len(),
        113,
        "five initialization,108 application,zero WTX"
    );
    assert_eq!(
        owner.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction)
    );
}

#[test]
fn already_valid_b_signatures_consume_no_exchange_and_mixed_inputs_only_sign_missing() {
    for (inputs, retained, expected) in [(1, vec![0], 0), (3, vec![0, 2], 1)] {
        let (mut owner, _broker, trace) =
            approval(1, &fixture::psbt_with_existing_b(inputs, &retained));
        owner
            .handle_event(NormalProcessEventV2::HoldCompleted)
            .expect("existing signature plan");
        assert_eq!(owner.sign_attempts(), expected);
        assert_eq!(trace.sign_count(), expected);
        assert_eq!(
            owner.stage(),
            NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction)
        );
    }
}

#[test]
fn binding_rejections_never_reach_sign() {
    for fault in [
        Fault::InfoProfile,
        Fault::InfoLifecycle,
        Fault::InfoWallet,
        Fault::InfoFingerprint,
        Fault::InfoXpub,
        Fault::Descriptor,
    ] {
        let (descriptor, clock, trace) = fixture::rig(1);
        trace.set_fault(fault);
        assert!(Owner::start(b"01", descriptor, clock).is_err(), "{fault:?}");
        assert_eq!(trace.sign_count(), 0);
        assert!(trace.descriptor_dropped());
    }
}

#[test]
fn first_middle_and_last_failed_sign_are_absorbing_with_no_partial_export() {
    for ordinal in [1, 2, 3] {
        let (mut owner, _broker, trace) = approval(1, &fixture::psbt_with_inputs(3));
        trace.set_fault(Fault::Sign {
            ordinal,
            kind: SignFault::Removed,
        });
        let error = owner
            .handle_event(NormalProcessEventV2::HoldCompleted)
            .err()
            .expect("removed");
        assert_eq!(error.name(), "Sec1210DescriptorClosed");
        assert_eq!(trace.sign_count(), ordinal);
        assert_absorbed(&mut owner, &trace, error, true);
    }
}

#[test]
fn signature_and_transport_rejections_preserve_their_first_names() {
    for (fault, name) in [
        (SignFault::WrongReview, "SigningBindingRejected"),
        (SignFault::WrongIndex, "SigningBindingRejected"),
        (SignFault::WrongKey, "CardSignatureKeyMismatch"),
        (SignFault::MalformedDer, "CardSignatureMalformed"),
        (SignFault::Invalid, "CardSignatureInvalid"),
        (SignFault::ReadFailure, "Sec1210DescriptorReadFailed"),
        (SignFault::ShortWrite, "Sec1210PartialWrite"),
        (SignFault::WriteFailure, "Sec1210DescriptorWriteFailed"),
        (SignFault::TimedOut, "Sec1210DeadlineExceeded"),
        (SignFault::BadChecksum, "Sec1210ChecksumRejected"),
        (SignFault::WrongSession, "SessionIdMismatch"),
        (SignFault::WrongCounter, "SequenceRejected"),
    ] {
        let (mut owner, _broker, trace) = approval(1, &fixture::psbt());
        trace.set_fault(Fault::Sign {
            ordinal: 1,
            kind: fault,
        });
        let error = owner
            .handle_event(NormalProcessEventV2::HoldCompleted)
            .err()
            .expect("fault");
        assert_eq!(error.name(), name, "{fault:?}");
        assert_absorbed(&mut owner, &trace, error, true);
    }
}

#[test]
fn high_s_is_normalized_and_repeated_r_rejected_by_the_existing_owner() {
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt());
    trace.set_fault(Fault::Sign {
        ordinal: 1,
        kind: SignFault::HighS,
    });
    owner
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("high S normalization");
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt_with_inputs(3));
    trace.set_fault(Fault::Sign {
        ordinal: 2,
        kind: SignFault::Repeated,
    });
    let error = owner
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .err()
        .expect("repeated r");
    assert_eq!(error.name(), "CardSignatureRepeatedR");
    assert_absorbed(&mut owner, &trace, error, true);
}

#[test]
fn pre_sign_failure_and_drop_do_not_claim_a_card_signature() {
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt());
    let error = owner
        .handle_event(NormalProcessEventV2::CardRemoved)
        .err()
        .expect("removed beforeapproval");
    assert_eq!(trace.sign_count(), 0);
    assert_absorbed(&mut owner, &trace, error, false);
    let (owner, _broker, trace) = approval(1, &fixture::psbt());
    drop(owner);
    assert!(trace.descriptor_dropped());
    assert_eq!(trace.sign_count(), 0);
}

#[test]
fn fragmented_frames_and_clock_failure_use_the_same_owner() {
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt());
    trace.set_fragment_bytes(1);
    owner
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("single byte fragments");
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt());
    trace.set_clock_script([Err(Sec1210ClockErrorV2)]);
    let error = owner
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .err()
        .expect("clock failure");
    assert_eq!(error.name(), "Sec1210ClockFailed");
    assert_absorbed(&mut owner, &trace, error, true);
}

#[cfg(feature = "fuzzing")]
#[test]
fn partial_sign_failure_and_drop_release_delegated_wiping_owners() {
    use qk_core::fuzz::{reset_wiped_bytes, wiped_bytes};
    let (mut owner, _broker, trace) = approval(1, &fixture::psbt_with_inputs(3));
    trace.set_fault(Fault::Sign {
        ordinal: 2,
        kind: SignFault::Removed,
    });
    reset_wiped_bytes();
    let error = owner
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .err()
        .expect("partial failure");
    assert!(
        wiped_bytes() > 0,
        "delegated fixed and allocated owners clear on failure"
    );
    assert_absorbed(&mut owner, &trace, error, true);
    let (owner, _broker, trace) = approval(1, &fixture::psbt());
    reset_wiped_bytes();
    drop(owner);
    assert!(
        wiped_bytes() > 0,
        "drop clears the retained approval/input material"
    );
    assert!(trace.descriptor_dropped());
}

#[cfg(feature = "fuzzing")]
#[test]
fn ring_fenced_constructor_has_reproducible_public_identities_and_closed_exhaustion() {
    let mut outputs = Vec::new();
    for _ in 0..2 {
        let (descriptor, clock, trace) = fixture::rig(1);
        let (owner, opening) = Owner::fuzz_start(b"01", descriptor, clock, [0x72; 12], 0)
            .expect("deterministic public owner");
        outputs.push((trace.apdus(), opening.frame_bytes().to_vec()));
        drop(owner);
        assert!(trace.descriptor_dropped());
    }
    assert_eq!(outputs[0], outputs[1]);
    let (descriptor, clock, trace) = fixture::rig(1);
    let result = Owner::fuzz_start(b"01", descriptor, clock, [0x72; 12], u32::MAX);
    assert_eq!(
        result.err().expect("exhausted identity").name(),
        "CardSessionIdentityExhausted"
    );
    assert!(trace.descriptor_dropped());
    assert_eq!(trace.sign_count(), 0);
}
