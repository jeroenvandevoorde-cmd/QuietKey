#![allow(clippy::panic, clippy::unwrap_used)]

use qk_card_protocol::{
    allowed_operations, A2Purpose, CommandRef, DescriptorSelector, EnvelopeRef, Lifecycle, Mode,
    ProtocolError, ResponseRef, SessionTracker, MAX_AGGREGATE_BYTES, MAX_EXCHANGES,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_SIGNATURES,
};

const SESSION: [u8; 16] = [0x11; 16];
const WALLET: [u8; 32] = [0x22; 32];
const REVIEW: [u8; 32] = [0x33; 32];
const DIGEST: [u8; 32] = [0x44; 32];
const OTHER_SESSION: [u8; 16] = [0x99; 16];
const ZERO16: [u8; 16] = [0; 16];
const ZERO32: [u8; 32] = [0; 32];
const ZERO4: [u8; 4] = [0; 4];
const ZERO78: [u8; 78] = [0; 78];
const D192: [u8; 192] = [0x55; 192];
const D114: [u8; 114] = [0x66; 114];
const CHUNK192: [u8; 192] = [0x77; 192];
const PUBLIC_KEY: [u8; 33] = [0x02; 33];
const DER: [u8; 8] = [0x30, 6, 2, 1, 1, 2, 1, 1];
const DER72: [u8; 72] = [0x30; 72];

fn env(sequence: u32) -> EnvelopeRef<'static> {
    EnvelopeRef::new(&SESSION, sequence)
}

fn info(sequence: u32) -> CommandRef<'static> {
    CommandRef::GetInfo {
        envelope: env(sequence),
    }
}

fn info_reply(session_id: &'static [u8; 16], sequence: u32) -> ResponseRef<'static> {
    ResponseRef::GetInfo {
        envelope: EnvelopeRef::new(session_id, sequence),
        record_version: 1,
        lifecycle: 0,
        profile: 0,
        role: 2,
        instance_id: &ZERO16,
        wallet_id: &ZERO32,
        origin_fingerprint: &ZERO4,
        account_xpub: &ZERO78,
        allowed_operations: 0x0011,
    }
}

fn read_reply(
    session_id: &'static [u8; 16],
    sequence: u32,
    selector: DescriptorSelector,
    offset: u16,
) -> ResponseRef<'static> {
    ResponseRef::ReadDChunk {
        envelope: EnvelopeRef::new(session_id, sequence),
        selector,
        offset,
        bytes: if offset == 0 { &D192 } else { &D114 },
    }
}

fn export_reply(
    session_id: &'static [u8; 16],
    sequence: u32,
    purpose: A2Purpose,
) -> ResponseRef<'static> {
    ResponseRef::ExportA2 {
        envelope: EnvelopeRef::new(session_id, sequence),
        purpose,
        a2: &ZERO32,
    }
}

fn sign_reply(
    session_id: &'static [u8; 16],
    sequence: u32,
    review_hash: &'static [u8; 32],
    input_index: u32,
    signature_der: &'static [u8],
) -> ResponseRef<'static> {
    ResponseRef::SignDigest {
        envelope: EnvelopeRef::new(session_id, sequence),
        review_hash,
        input_index,
        public_key: &PUBLIC_KEY,
        signature_der,
    }
}

fn assert_finish_failure(
    mode: Mode,
    command: CommandRef<'static>,
    request_bytes: usize,
    response: ResponseRef<'static>,
    response_bytes: usize,
    expected: ProtocolError,
) {
    let mut tracker = SessionTracker::new(mode, &SESSION, 24, 23).unwrap();
    tracker.begin_exchange(command, request_bytes).unwrap();
    assert_eq!(
        tracker.finish_success(response, response_bytes),
        Err(expected)
    );
    assert!(tracker.is_terminated());
}

#[test]
fn operation_masks_and_invalid_lifecycle_mode_pairs_are_exact() {
    assert_eq!(
        allowed_operations(Lifecycle::Unprovisioned, Mode::Setup, false),
        Ok(0x0011)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Unprovisioned, Mode::KitRestore, false),
        Ok(0x0011)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Staging, Mode::Setup, false),
        Ok(0x00b1)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Staging, Mode::Setup, true),
        Ok(0x00d1)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Committed, Mode::Setup, false),
        Ok(0x0007)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Committed, Mode::Normal, false),
        Ok(0x000f)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Committed, Mode::KitRestore, false),
        Ok(0x0003)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Committed, Mode::Rescue, false),
        Ok(0x000f)
    );
    assert_eq!(
        allowed_operations(Lifecycle::RetiredError, Mode::Normal, false),
        Ok(0x0001)
    );
    assert_eq!(
        allowed_operations(Lifecycle::Unprovisioned, Mode::Normal, false),
        Err(ProtocolError::LifecycleRejected)
    );
}

#[test]
fn requests_are_single_outstanding_and_strictly_sequenced() {
    let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    tracker.begin_exchange(info(1), 27).unwrap();
    assert_eq!(
        tracker.begin_exchange(info(1), 27),
        Err(ProtocolError::SessionStateRejected)
    );
    assert!(tracker.is_terminated());

    let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    tracker.begin_exchange(info(1), 27).unwrap();
    tracker
        .finish_success(info_reply(&SESSION, 1), 160)
        .unwrap();
    assert_eq!(tracker.next_sequence(), 2);
    assert_eq!(tracker.exchange_count(), 2);
    assert_eq!(
        tracker.begin_exchange(info(3), 27),
        Err(ProtocolError::SequenceRejected)
    );
}

#[test]
fn descriptor_reads_and_a2_are_ordered_and_one_use() {
    let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    let expected = [
        (DescriptorSelector::Receive, 0),
        (DescriptorSelector::Receive, 192),
        (DescriptorSelector::Change, 0),
        (DescriptorSelector::Change, 192),
    ];
    for (index, (selector, offset)) in expected.into_iter().enumerate() {
        let sequence = u32::try_from(index + 1).unwrap();
        tracker
            .begin_exchange(
                CommandRef::ReadDChunk {
                    envelope: env(sequence),
                    selector,
                    offset,
                },
                30,
            )
            .unwrap();
        let response_bytes = if offset == 0 { 218 } else { 140 };
        tracker
            .finish_success(
                read_reply(&SESSION, sequence, selector, offset),
                response_bytes,
            )
            .unwrap();
    }
    tracker
        .begin_exchange(
            CommandRef::ExportA2 {
                envelope: env(5),
                purpose: A2Purpose::Normal,
            },
            28,
        )
        .unwrap();
    tracker
        .finish_success(export_reply(&SESSION, 5, A2Purpose::Normal), 56)
        .unwrap();
    assert_eq!(
        tracker.begin_exchange(
            CommandRef::ExportA2 {
                envelope: env(6),
                purpose: A2Purpose::Normal,
            },
            28,
        ),
        Err(ProtocolError::ModeOrOperationRejected)
    );

    let mut wrong = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    assert_eq!(
        wrong.begin_exchange(
            CommandRef::ReadDChunk {
                envelope: env(1),
                selector: DescriptorSelector::Change,
                offset: 0,
            },
            30,
        ),
        Err(ProtocolError::ModeOrOperationRejected)
    );
}

fn sign(
    sequence: u32,
    wallet_id: &'static [u8; 32],
    review_hash: &'static [u8; 32],
    input_index: u32,
) -> CommandRef<'static> {
    CommandRef::SignDigest {
        envelope: env(sequence),
        wallet_id,
        review_hash,
        input_index,
        branch: 0,
        child_index: 7,
        digest: &DIGEST,
    }
}

#[test]
fn signing_binding_and_input_order_are_exact() {
    let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    tracker
        .begin_exchange(sign(1, &WALLET, &REVIEW, 4), 132)
        .unwrap();
    tracker
        .finish_success(sign_reply(&SESSION, 1, &REVIEW, 4, &DER72), 165)
        .unwrap();
    tracker
        .begin_exchange(sign(2, &WALLET, &REVIEW, 9), 132)
        .unwrap();
    tracker
        .finish_success(sign_reply(&SESSION, 2, &REVIEW, 9, &DER72), 165)
        .unwrap();
    assert_eq!(
        tracker.begin_exchange(sign(3, &WALLET, &REVIEW, 9), 132),
        Err(ProtocolError::SigningBindingRejected)
    );

    static OTHER: [u8; 32] = [0x99; 32];
    let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    tracker
        .begin_exchange(sign(1, &WALLET, &REVIEW, 0), 132)
        .unwrap();
    tracker
        .finish_success(sign_reply(&SESSION, 1, &REVIEW, 0, &DER72), 165)
        .unwrap();
    assert_eq!(
        tracker.begin_exchange(sign(2, &OTHER, &REVIEW, 1), 132),
        Err(ProtocolError::SigningBindingRejected)
    );
}

#[test]
fn responses_require_exact_session_sequence_variant_and_echoes() {
    assert_finish_failure(
        Mode::Normal,
        info(1),
        27,
        info_reply(&OTHER_SESSION, 1),
        160,
        ProtocolError::SessionIdMismatch,
    );
    assert_finish_failure(
        Mode::Normal,
        info(1),
        27,
        info_reply(&SESSION, 2),
        160,
        ProtocolError::SequenceRejected,
    );
    assert_finish_failure(
        Mode::Normal,
        sign(1, &WALLET, &REVIEW, 4),
        132,
        info_reply(&SESSION, 1),
        160,
        ProtocolError::SessionStateRejected,
    );
    assert_finish_failure(
        Mode::Normal,
        CommandRef::ReadDChunk {
            envelope: env(1),
            selector: DescriptorSelector::Receive,
            offset: 0,
        },
        30,
        read_reply(&SESSION, 1, DescriptorSelector::Change, 0),
        218,
        ProtocolError::ModeOrOperationRejected,
    );
    assert_finish_failure(
        Mode::Normal,
        CommandRef::ReadDChunk {
            envelope: env(1),
            selector: DescriptorSelector::Receive,
            offset: 0,
        },
        30,
        ResponseRef::ReadDChunk {
            envelope: env(1),
            selector: DescriptorSelector::Receive,
            offset: 192,
            bytes: &D192,
        },
        218,
        ProtocolError::ModeOrOperationRejected,
    );
    assert_finish_failure(
        Mode::Normal,
        CommandRef::ExportA2 {
            envelope: env(1),
            purpose: A2Purpose::Normal,
        },
        28,
        export_reply(&SESSION, 1, A2Purpose::Rescue),
        56,
        ProtocolError::ModeOrOperationRejected,
    );
    assert_finish_failure(
        Mode::Setup,
        CommandRef::WriteChunk {
            envelope: env(1),
            offset: 0,
            bytes: &CHUNK192,
        },
        221,
        ResponseRef::WriteChunk {
            envelope: env(1),
            next_offset: 384,
        },
        25,
        ProtocolError::ProvisioningOrderRejected,
    );
    assert_finish_failure(
        Mode::Normal,
        sign(1, &WALLET, &REVIEW, 4),
        132,
        sign_reply(&SESSION, 1, &DIGEST, 4, &DER),
        101,
        ProtocolError::SigningBindingRejected,
    );
    assert_finish_failure(
        Mode::Normal,
        sign(1, &WALLET, &REVIEW, 4),
        132,
        sign_reply(&SESSION, 1, &REVIEW, 5, &DER),
        101,
        ProtocolError::SigningBindingRejected,
    );
}

#[test]
fn provisioning_success_variants_and_next_offset_are_validated() {
    let mut tracker = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    tracker
        .begin_exchange(
            CommandRef::BeginProvision {
                envelope: env(1),
                ordinal: 1,
                provisioning_nonce: &[0x88; 12],
            },
            40,
        )
        .unwrap();
    tracker
        .finish_success(ResponseRef::BeginProvision { envelope: env(1) }, 23)
        .unwrap();
    tracker
        .begin_exchange(
            CommandRef::WriteChunk {
                envelope: env(2),
                offset: 0,
                bytes: &CHUNK192,
            },
            221,
        )
        .unwrap();
    tracker
        .finish_success(
            ResponseRef::WriteChunk {
                envelope: env(2),
                next_offset: 192,
            },
            25,
        )
        .unwrap();
    assert_eq!(tracker.next_sequence(), 3);
}

#[test]
fn signature_cap_is_exact_and_uses_one_use_exhaustion_status() {
    let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    for index in 0..u32::from(MAX_SIGNATURES) {
        tracker
            .begin_exchange(sign(index + 1, &WALLET, &REVIEW, index), 132)
            .unwrap();
        tracker
            .finish_success(sign_reply(&SESSION, index + 1, &REVIEW, index, &DER), 101)
            .unwrap();
    }
    assert_eq!(
        tracker.begin_exchange(
            sign(
                u32::from(MAX_SIGNATURES) + 1,
                &WALLET,
                &REVIEW,
                u32::from(MAX_SIGNATURES),
            ),
            132,
        ),
        Err(ProtocolError::ModeOrOperationRejected)
    );
    assert!(tracker.is_terminated());
}

#[test]
fn exchange_and_aggregate_caps_fail_closed() {
    let aggregate_ceiling = usize::from(MAX_EXCHANGES) * (MAX_REQUEST_BYTES + MAX_RESPONSE_BYTES);
    assert_eq!(aggregate_ceiling, 56_192);
    assert!(aggregate_ceiling < MAX_AGGREGATE_BYTES);
    assert_eq!(
        SessionTracker::new(Mode::Setup, &SESSION, MAX_AGGREGATE_BYTES, 1)
            .err()
            .unwrap(),
        ProtocolError::SessionStateRejected
    );
    assert_eq!(
        SessionTracker::new(Mode::Setup, &SESSION, 23, 23)
            .err()
            .unwrap(),
        ProtocolError::SessionStateRejected
    );

    let mut oversized_request = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    assert_eq!(
        oversized_request.begin_exchange(info(1), MAX_REQUEST_BYTES + 1),
        Err(ProtocolError::SessionStateRejected)
    );
    let mut wrong_request_length = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    assert_eq!(
        wrong_request_length.begin_exchange(info(1), 26),
        Err(ProtocolError::SessionStateRejected)
    );
    let mut oversized_response = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    oversized_response.begin_exchange(info(1), 27).unwrap();
    assert_eq!(
        oversized_response.finish_success(info_reply(&SESSION, 1), MAX_RESPONSE_BYTES + 1,),
        Err(ProtocolError::SessionStateRejected)
    );
    assert!(oversized_response.is_terminated());

    let mut wrong_response_length = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    wrong_response_length.begin_exchange(info(1), 27).unwrap();
    assert_eq!(
        wrong_response_length.finish_success(info_reply(&SESSION, 1), 159),
        Err(ProtocolError::SessionStateRejected)
    );
    let mut mismatched_response_shape =
        SessionTracker::new(Mode::Normal, &SESSION, 24, 23).unwrap();
    mismatched_response_shape
        .begin_exchange(sign(1, &WALLET, &REVIEW, 0), 132)
        .unwrap();
    assert_eq!(
        mismatched_response_shape.finish_success(sign_reply(&SESSION, 1, &REVIEW, 0, &DER), 165,),
        Err(ProtocolError::SessionStateRejected)
    );

    let mut tracker = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    for sequence in 1..MAX_EXCHANGES {
        tracker
            .begin_exchange(info(u32::from(sequence)), 27)
            .unwrap();
        tracker
            .finish_success(info_reply(&SESSION, u32::from(sequence)), 160)
            .unwrap();
    }
    assert_eq!(tracker.exchange_count(), MAX_EXCHANGES);
    assert_eq!(
        tracker.begin_exchange(info(u32::from(MAX_EXCHANGES)), 27),
        Err(ProtocolError::SessionStateRejected)
    );
}

#[test]
fn commit_abort_and_named_rejection_terminate() {
    let mut commit = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    commit
        .begin_exchange(CommandRef::Commit { envelope: env(1) }, 27)
        .unwrap();
    commit
        .finish_success(ResponseRef::Commit { envelope: env(1) }, 23)
        .unwrap();
    assert!(commit.is_terminated());

    let mut abort = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    abort
        .begin_exchange(CommandRef::Abort { envelope: env(1) }, 27)
        .unwrap();
    abort
        .finish_success(ResponseRef::Abort { envelope: env(1) }, 23)
        .unwrap();
    assert!(abort.is_terminated());

    let mut rejected = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    rejected.begin_exchange(info(1), 27).unwrap();
    rejected.finish_rejection(2).unwrap();
    assert!(rejected.is_terminated());
    assert_eq!(
        rejected.finish_rejection(2),
        Err(ProtocolError::SessionStateRejected)
    );

    let mut no_outstanding = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    assert_eq!(
        no_outstanding.finish_rejection(2),
        Err(ProtocolError::SessionStateRejected)
    );
    assert!(no_outstanding.is_terminated());

    let mut malformed_rejection = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    malformed_rejection.begin_exchange(info(1), 27).unwrap();
    assert_eq!(
        malformed_rejection.finish_rejection(3),
        Err(ProtocolError::SessionStateRejected)
    );
    assert!(malformed_rejection.is_terminated());

    let mut cap_rejection = SessionTracker::new(Mode::Setup, &SESSION, 24, 23).unwrap();
    cap_rejection.begin_exchange(info(1), 27).unwrap();
    assert_eq!(
        cap_rejection.finish_rejection(MAX_AGGREGATE_BYTES),
        Err(ProtocolError::SessionStateRejected)
    );
    assert!(cap_rejection.is_terminated());
}
