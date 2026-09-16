use qk_t1::{
    Error, Phase, RawBlock, RawError as E, RawSession as S, RAW_APDU_BUDGET_MS,
    RAW_BASE_COMMAND_BUDGET_MS, RAW_BWT_MS, RAW_MAX_APDUS, RAW_MAX_BLOCK_BYTES,
    RAW_MAX_COMMAND_BYTES, RAW_MAX_EXCHANGES, RAW_MAX_RESPONSE_BYTES, RAW_MAX_WTX,
    RAW_MAX_WTX_MULTIPLIER,
};

const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const RAW_SESSION_SOURCE: &str = include_str!("../src/raw_session.rs");
const WIPE_SOURCE: &str = include_str!("../src/wipe.rs");

fn frame(pcb: u8, inf: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, pcb, inf.len() as u8];
    bytes.extend_from_slice(inf);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

fn send(session: &mut S, now: u64) -> RawBlock {
    let block = session.next_block(now).unwrap();
    session.written(block.as_bytes().len(), now).unwrap();
    block
}

fn initialized() -> S {
    let mut session = S::default();
    session.begin_ifs(0).unwrap();
    assert_eq!(send(&mut session, 0).as_bytes(), [0, 0xc1, 1, 0xfe, 0x3e]);
    session.receive(&[0, 0xe1, 1, 0xfe, 0x1e], 1).unwrap();
    session
}

fn pending() -> S {
    let mut session = initialized();
    session.begin(&[0xaa], 10).unwrap();
    send(&mut session, 10);
    session
}

fn assert_terminal(session: &mut S, expected: E, now: u64) {
    assert_eq!(session.failure(), Some(expected));
    assert_eq!(session.phase(), Phase::Failed);
    assert_eq!(session.next_block(now), Err(expected));
    assert_eq!(session.written(0, now), Err(expected));
    assert_eq!(session.receive(&[], now), Err(expected));
    assert_eq!(session.begin(&[0], now), Err(expected));
    assert_eq!(session.begin_ifs(now), Err(expected));
    assert_eq!(session.tick(0), Err(expected));
}

#[test]
fn constants_and_fixed_ifs_do_not_change_the_old_limits_or_sequences() {
    assert_eq!((RAW_MAX_COMMAND_BYTES, RAW_MAX_RESPONSE_BYTES), (254, 254));
    assert_eq!((RAW_MAX_BLOCK_BYTES, RAW_MAX_APDUS), (258, 128));
    assert_eq!(
        (RAW_MAX_EXCHANGES, RAW_MAX_WTX, RAW_MAX_WTX_MULTIPLIER),
        (16, 8, 24)
    );
    assert_eq!(
        (RAW_APDU_BUDGET_MS, RAW_BASE_COMMAND_BUDGET_MS, RAW_BWT_MS),
        (30_000, 5_000, 1_190)
    );
    assert_eq!(
        (qk_t1::MAX_COMMAND_BYTES, qk_t1::MAX_RESPONSE_BYTES),
        (30, 218)
    );
    assert_eq!((qk_t1::MAX_APDUS, qk_t1::MAX_EXCHANGES), (8, 16));
    let mut session = S::default();
    assert_eq!(session.receive_bound(), 36);
    assert!(!session.ifs_accepted());
    session.begin_ifs(1).unwrap();
    let request = send(&mut session, 2);
    assert_eq!(request.as_bytes(), [0, 0xc1, 1, 0xfe, 0x3e]);
    assert_eq!((request.bwi(), request.command_allowance_ms()), (0, 5_000));
    session.receive(&frame(0xe1, &[0xfe]), 3).unwrap();
    assert_eq!(session.receive_bound(), 258);
    assert!(session.ifs_accepted());
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (0, 0)
    );
    assert_eq!(session.completed_apdus(), 0);
    assert_eq!(session.phase(), Phase::Idle);
}

#[test]
fn no_apdu_is_available_before_ifs_and_failure_stays_first() {
    let mut session = S::default();
    let error = E::T1(Error::StateRejected);
    assert_eq!(session.begin(&[1], 0), Err(error));
    assert_terminal(&mut session, error, 50_000);
}

#[test]
fn ifs_echo_gates_length_checksum_nad_and_exact_control_value() {
    let cases = [
        (vec![0, 0xe1, 1, 0xfe], Error::BlockLengthRejected),
        (vec![0, 0xe1, 1, 0xfe, 0x1f], Error::ChecksumRejected),
        (vec![1, 0xe1, 1, 0xfe, 0x1f], Error::NadRejected),
        (frame(0xe1, &[0xfd]), Error::IfsRejected),
        (frame(0xc1, &[0xfe]), Error::IfsRejected),
        (frame(0xe1, &[]), Error::ControlLengthRejected),
        (frame(0xc3, &[1]), Error::WtxRejected),
        (frame(0x80, &[]), Error::UnexpectedRBlock),
        (frame(0, &[0x90, 0]), Error::IfsRejected),
    ];
    for (reply, error) in cases {
        let mut session = S::default();
        session.begin_ifs(0).unwrap();
        send(&mut session, 0);
        assert_eq!(session.receive(&reply, 1), Err(E::T1(error)));
        assert!(!session.ifs_accepted());
        assert_eq!(session.receive_bound(), 36);
        assert_terminal(&mut session, E::T1(error), 2);
    }
}

#[test]
fn repeat_or_unsolicited_ifs_is_named_and_never_resets_bits() {
    let mut session = initialized();
    assert_eq!(
        session.receive(&frame(0xe1, &[0xfe]), 2),
        Err(E::T1(Error::IfsRejected))
    );
    let mut session = initialized();
    assert_eq!(session.begin_ifs(2), Err(E::T1(Error::StateRejected)));
    let mut session = pending();
    assert_eq!(
        session.receive(&frame(0xc1, &[0xfe]), 11),
        Err(E::T1(Error::IfsRejected))
    );
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (0, 0)
    );
}

#[test]
fn ifs_has_its_own_five_second_deadline() {
    let mut before = S::default();
    before.begin_ifs(10).unwrap();
    send(&mut before, 10);
    before.receive(&frame(0xe1, &[0xfe]), 5_009).unwrap();
    let mut at = S::default();
    at.begin_ifs(10).unwrap();
    send(&mut at, 10);
    assert_eq!(
        at.receive(&frame(0xe1, &[0xfe]), 5_010),
        Err(E::T1(Error::DeadlineExceeded))
    );
}

#[test]
fn commands_and_responses_are_raw_and_bounded_at_254() {
    for len in [1, 30, 132, 254] {
        let mut session = initialized();
        let command = vec![0x91; len];
        session.begin(&command, 2).unwrap();
        let block = send(&mut session, 2);
        assert_eq!(block.as_bytes(), frame(0, &command));
        let response = vec![0x37; len];
        session.receive(&frame(0, &response), 3).unwrap();
        assert_eq!(session.response(), response);
        assert_eq!(session.completed_apdus(), 1);
    }
    for len in [0, 255] {
        let mut session = initialized();
        assert_eq!(
            session.begin(&vec![0; len], 2),
            Err(E::T1(Error::CommandLengthRejected))
        );
    }
    let mut session = pending();
    assert_eq!(
        session.receive(&frame(0, &[0; 255]), 11),
        Err(E::T1(Error::BlockLengthRejected))
    );
}

#[test]
fn an_empty_raw_response_is_not_mistaken_for_a_policy_verification() {
    let mut session = pending();
    session.receive(&frame(0, &[]), 11).unwrap();
    assert!(session.response().is_empty());
    assert_eq!(session.phase(), Phase::Complete);
    assert_eq!(session.completed_apdus(), 1);
}

#[test]
fn full_128_apdu_traversal_tracks_independent_bits_and_rejects_129() {
    let mut session = initialized();
    for index in 0..128usize {
        let now = 2 + index as u64;
        session.begin(&[index as u8; 132], now).unwrap();
        let block = send(&mut session, now);
        assert_eq!(block.as_bytes()[1], ((index & 1) as u8) << 6);
        session
            .receive(&frame(((index & 1) as u8) << 6, &[index as u8; 165]), now)
            .unwrap();
        assert_eq!(session.completed_apdus(), index + 1);
        assert_eq!(session.send_sequence(), ((index + 1) & 1) as u8);
        assert_eq!(session.receive_sequence(), ((index + 1) & 1) as u8);
    }
    assert_eq!(
        session.begin(&[0], 130),
        Err(E::T1(Error::ApduLimitExceeded))
    );
}

#[test]
fn wtx_1_2_and_24_echo_exactly_without_completing_or_toggling() {
    for multiplier in [1, 2, 24] {
        let mut session = pending();
        session.receive(&frame(0xc3, &[multiplier]), 11).unwrap();
        assert_eq!(session.phase(), Phase::Ready);
        assert_eq!(
            (session.send_sequence(), session.receive_sequence()),
            (0, 0)
        );
        assert_eq!(session.completed_apdus(), 0);
        let reply = send(&mut session, 12);
        assert_eq!(reply.as_bytes(), frame(0xe3, &[multiplier]));
        assert_eq!(reply.bwi(), multiplier);
        assert_eq!(
            reply.command_allowance_ms(),
            5_000.max(u64::from(multiplier) * 1_190)
        );
        assert_eq!(session.apdu_deadline_ms(), Some(30_010));
        assert_eq!(session.wtx_multipliers(), [multiplier]);
        session.receive(&frame(0, &[0x90, 0]), 13).unwrap();
        assert_eq!(session.exchanges(), 2);
        assert_eq!(
            (session.send_sequence(), session.receive_sequence()),
            (1, 1)
        );
        assert_eq!(session.completed_apdus(), 1);
    }
}

#[test]
fn wtx_zero_25_and_255_are_named_before_any_response() {
    for multiplier in [0, 25, 255] {
        let mut session = pending();
        assert_eq!(
            session.receive(&frame(0xc3, &[multiplier]), 11),
            Err(E::WtxMultiplierRejected)
        );
        assert_eq!(session.wtx_count(), 0);
        assert_eq!(session.total_wtx_count(), 0);
        assert_terminal(&mut session, E::WtxMultiplierRejected, 12);
    }
}

#[test]
fn eight_wtx_are_allowed_ninth_is_terminal_and_no_ack_is_queued() {
    let mut session = pending();
    for index in 0..8 {
        session.receive(&frame(0xc3, &[1]), 11 + index).unwrap();
        send(&mut session, 11 + index);
    }
    assert_eq!(session.exchanges(), 9);
    assert_eq!(session.wtx_count(), 8);
    assert_eq!(session.total_wtx_count(), 8);
    assert_eq!(
        session.receive(&frame(0xc3, &[1]), 20),
        Err(E::WtxLimitExceeded)
    );
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (0, 0)
    );
    assert_terminal(&mut session, E::WtxLimitExceeded, 21);
}

#[test]
fn per_apdu_wtx_counter_resets_only_for_the_next_apdu() {
    let mut session = pending();
    for multiplier in [24, 2, 1] {
        session.receive(&frame(0xc3, &[multiplier]), 11).unwrap();
        let reply = send(&mut session, 11);
        assert_eq!(
            reply.command_allowance_ms(),
            5_000.max(u64::from(multiplier) * 1_190)
        );
        assert_eq!(session.apdu_deadline_ms(), Some(30_010));
    }
    session.receive(&frame(0, &[0x90, 0]), 12).unwrap();
    assert_eq!((session.wtx_count(), session.total_wtx_count()), (3, 3));
    session.begin(&[1], 13).unwrap();
    assert_eq!((session.wtx_count(), session.total_wtx_count()), (0, 3));
    assert_eq!(session.apdu_deadline_ms(), Some(30_013));
}

#[test]
fn wtx_never_extends_the_absolute_apdu_clock() {
    let mut session = pending();
    session.receive(&frame(0xc3, &[24]), 29_009).unwrap();
    let reply = send(&mut session, 29_009);
    assert_eq!(reply.command_allowance_ms(), 28_560);
    assert_eq!(session.apdu_deadline_ms(), Some(30_010));
    session.tick(30_009).unwrap();
    assert_eq!(
        session.receive(&frame(0, &[0x90, 0]), 30_010),
        Err(E::T1(Error::DeadlineExceeded))
    );
    assert_eq!(session.completed_apdus(), 0);
}

#[test]
fn accepted_extended_response_can_arrive_after_five_seconds() {
    let mut session = pending();
    session.receive(&frame(0xc3, &[24]), 11).unwrap();
    send(&mut session, 11);
    session.receive(&frame(0, &[0x90, 0]), 7_000).unwrap();
    assert_eq!(session.phase(), Phase::Complete);
}

#[test]
fn apdu_deadline_includes_claim_write_and_evidence_work() {
    for step in 0..3 {
        let mut session = initialized();
        session.begin(&[0], 10).unwrap();
        if step > 0 {
            session.next_block(11).unwrap();
        }
        if step > 1 {
            session.written(5, 12).unwrap();
        }
        let result = match step {
            0 => session.next_block(30_010).map(|_| ()),
            1 => session.written(5, 30_010),
            _ => session.receive(&frame(0, &[0x90, 0]), 30_010),
        };
        assert_eq!(result, Err(E::T1(Error::DeadlineExceeded)));
    }
}

#[test]
fn wtx_malformed_controls_fail_in_length_lrc_nad_order() {
    let cases = [
        (vec![0, 0xc3, 1, 1], Error::BlockLengthRejected),
        (vec![0, 0xc3, 1, 1, 0], Error::ChecksumRejected),
        (vec![1, 0xc3, 1, 1, 0xc2], Error::NadRejected),
        (frame(0xc3, &[]), Error::ControlLengthRejected),
        (frame(0xc3, &[1, 1]), Error::ControlLengthRejected),
        (frame(0xc7, &[1]), Error::PcbRejected),
    ];
    for (reply, error) in cases {
        let mut session = pending();
        assert_eq!(session.receive(&reply, 11), Err(E::T1(error)));
        assert_eq!(session.wtx_count(), 0);
    }
}

#[test]
fn unsolicited_wtx_response_and_out_of_phase_request_do_not_send() {
    for mut session in [initialized(), pending()] {
        assert_eq!(
            session.receive(&frame(0xe3, &[1]), 11),
            Err(E::WtxResponseRejected)
        );
        assert_terminal(&mut session, E::WtxResponseRejected, 12);
    }
    let mut session = initialized();
    assert_eq!(
        session.receive(&frame(0xc3, &[1]), 2),
        Err(E::T1(Error::StateRejected))
    );
}

#[test]
fn chaining_r_retransmission_resync_and_abort_stay_rejected() {
    let cases = [
        (frame(0x20, &[0]), E::ChainingRejected),
        (frame(0x80, &[]), E::T1(Error::UnexpectedRBlock)),
        (frame(0x81, &[]), E::T1(Error::RetransmissionRejected)),
        (frame(0xc0, &[]), E::T1(Error::ResynchRejected)),
        (frame(0xc2, &[]), E::T1(Error::AbortRejected)),
        (frame(0x40, &[0]), E::T1(Error::SequenceRejected)),
    ];
    for (reply, error) in cases {
        let mut session = pending();
        assert_eq!(session.receive(&reply, 11), Err(error));
        assert!(session.response().is_empty());
        assert_eq!(
            (session.send_sequence(), session.receive_sequence()),
            (0, 0)
        );
        assert_terminal(&mut session, error, 12);
    }
}

#[test]
fn duplicate_claim_write_and_response_are_not_retransmission_apis() {
    let mut session = initialized();
    session.begin(&[0], 2).unwrap();
    session.next_block(2).unwrap();
    assert_eq!(session.next_block(2), Err(E::T1(Error::StateRejected)));
    let mut session = pending();
    assert_eq!(session.written(5, 11), Err(E::T1(Error::StateRejected)));
    let mut session = pending();
    session.receive(&frame(0, &[1]), 11).unwrap();
    assert_eq!(
        session.receive(&frame(0, &[1]), 12),
        Err(E::T1(Error::StateRejected))
    );
}

#[test]
fn partial_write_clock_regression_and_clock_overflow_fail_closed() {
    let mut session = initialized();
    session.begin(&[0], 2).unwrap();
    session.next_block(2).unwrap();
    assert_eq!(session.written(4, 2), Err(E::T1(Error::PartialWrite)));
    assert_terminal(&mut session, E::T1(Error::PartialWrite), 50_000);
    let mut session = pending();
    assert_eq!(session.tick(9), Err(E::T1(Error::ClockRegression)));
    let mut session = initialized();
    session.begin(&[0], u64::MAX - 1).unwrap();
    assert_eq!(
        session.next_block(u64::MAX),
        Err(E::T1(Error::DeadlineExceeded))
    );
}

#[test]
fn every_new_error_has_its_pinned_name() {
    assert_eq!(E::WtxMultiplierRejected.name(), "T1WtxMultiplierRejected");
    assert_eq!(E::WtxLimitExceeded.name(), "T1WtxLimitExceeded");
    assert_eq!(E::WtxResponseRejected.name(), "T1WtxResponseRejected");
    assert_eq!(E::ChainingRejected.name(), "T1ChainingRejected");
    assert_eq!(E::T1(Error::ChecksumRejected).name(), "T1ChecksumRejected");
}

#[test]
fn hardened_contact_sources_confine_unsafe_and_remain_heap_free() {
    assert!(LIB_SOURCE.contains("#![deny(unsafe_code)]"));
    assert!(LIB_SOURCE.contains("#[allow(unsafe_code)]\nmod wipe;"));
    assert!(!RAW_SESSION_SOURCE.contains("unsafe"));
    assert!(!RAW_SESSION_SOURCE.contains("Vec<"));
    assert!(!RAW_SESSION_SOURCE.contains("Box<"));
    assert_eq!(WIPE_SOURCE.matches("unsafe {").count(), 1);
    assert_eq!(WIPE_SOURCE.matches("ptr::write_volatile").count(), 1);
    assert!(WIPE_SOURCE.contains("compiler_fence(Ordering::SeqCst);"));
}

#[test]
fn accepted_next_apdu_resets_current_storage_but_preserves_session_totals() {
    let mut session = pending();
    session.receive(&frame(0xc3, &[2]), 11).unwrap();
    send(&mut session, 11);
    session.receive(&frame(0, &[0xa5, 0x90, 0]), 12).unwrap();
    assert_eq!(session.response(), [0xa5, 0x90, 0]);
    assert_eq!(session.wtx_multipliers(), [2]);
    assert_eq!(session.total_wtx_count(), 1);

    session.begin(&[0x5a], 13).unwrap();
    assert!(session.response().is_empty());
    assert!(session.wtx_multipliers().is_empty());
    assert_eq!(session.total_wtx_count(), 1);
    assert_eq!(send(&mut session, 13).as_bytes(), frame(0x40, &[0x5a]));
    session.receive(&frame(0x40, &[0x90, 0]), 14).unwrap();
    assert_eq!(session.response(), [0x90, 0]);
}
