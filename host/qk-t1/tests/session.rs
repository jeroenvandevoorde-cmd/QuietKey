use qk_t1::{Error as E, Phase, Session, IFS_BUDGET_MS};

fn frame(sequence: u8, more: bool, inf: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0,
        sequence << 6 | if more { 0x20 } else { 0 },
        inf.len() as u8,
    ];
    bytes.extend_from_slice(inf);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}
fn send(session: &mut Session, now: u64) -> Vec<u8> {
    let block = session.next_block(now).unwrap();
    session.written(block.as_bytes().len(), now).unwrap();
    block.as_bytes().to_vec()
}
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn eight_frozen_readbacks_preserve_both_sequence_bits() {
    let mut session = Session::default();
    let mut now = 0;
    let mut expected_send = 0;
    let mut expected_receive = 0;
    let mut total_blocks = 0;
    let mut totals = (0, 0);
    let fixture = include_str!(
        "../../../bench/card-enrollment/tests/fixtures/sitting_committed_readback_v1.tsv"
    );
    for line in fixture.lines().skip(5) {
        let fields: Vec<_> = line.split('\t').collect();
        let command = hex(fields[3]);
        let expected = hex(fields[4]);
        totals.0 += command.len();
        totals.1 += expected.len();
        session.begin(&command, &expected, now).unwrap();
        for (index, chunk) in expected.chunks(32).enumerate() {
            let request = send(&mut session, now);
            assert_eq!(
                request[1],
                if index == 0 {
                    expected_send << 6
                } else {
                    0x80 | expected_receive << 4
                }
            );
            let more = (index + 1) * 32 < expected.len();
            now += 1;
            session
                .receive(&frame(expected_receive, more, chunk), now)
                .unwrap();
            expected_receive ^= 1;
            total_blocks += 1;
        }
        expected_send ^= 1;
        assert_eq!(session.phase(), Phase::Complete);
        assert_eq!(session.response_prefix(), expected);
        assert_eq!(session.send_sequence(), expected_send);
        assert_eq!(session.receive_sequence(), expected_receive);
    }
    assert_eq!(totals, (211, 957));
    assert_eq!(total_blocks, 33);
    assert_eq!(session.completed_apdus(), 8);
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (0, 1)
    );
    assert_eq!(
        session.begin(&[0], &[0x90, 0], now),
        Err(E::ApduLimitExceeded)
    );
}

#[test]
fn each_prefix_is_checked_before_any_ack_is_available() {
    let mut session = Session::default();
    session.begin(&[0], &[1, 2], 0).unwrap();
    send(&mut session, 0);
    assert_eq!(
        session.receive(&frame(0, true, &[9]), 1),
        Err(E::ResponseMismatch)
    );
    assert_eq!(session.next_block(1), Err(E::ResponseMismatch));
    assert!(session.response_prefix().is_empty());
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (0, 0)
    );
}

#[test]
fn response_bounds_and_final_lengths_are_exact() {
    for (expected, payload, more) in [
        (&[1][..], &[1, 2][..], false),
        (&[1, 2][..], &[1][..], false),
        (&[1][..], &[1][..], true),
    ] {
        let mut session = Session::default();
        session.begin(&[0], expected, 0).unwrap();
        send(&mut session, 0);
        assert_eq!(
            session.receive(&frame(0, more, payload), 1),
            Err(E::ResponseLengthRejected)
        );
        assert!(session.response_prefix().is_empty());
    }
}

#[test]
fn maximum_response_uses_seven_new_i_blocks() {
    let expected = [0x55; 218];
    let mut session = Session::default();
    session.begin(&[0xaa; 30], &expected, 0).unwrap();
    for (index, chunk) in expected.chunks(32).enumerate() {
        send(&mut session, index as u64);
        session
            .receive(&frame((index & 1) as u8, index < 6, chunk), index as u64)
            .unwrap();
    }
    assert_eq!(session.exchanges(), 7);
    assert_eq!(session.response_prefix(), expected);
    assert_eq!(session.completed_apdus(), 1);
}

#[test]
fn duplicate_and_wrong_sequence_never_insert_bytes() {
    let mut session = Session::default();
    session.begin(&[0], &[1, 2], 0).unwrap();
    send(&mut session, 0);
    session.receive(&frame(0, true, &[1]), 1).unwrap();
    send(&mut session, 1);
    assert_eq!(
        session.receive(&frame(0, false, &[1]), 2),
        Err(E::SequenceRejected)
    );
    assert_eq!(session.response_prefix(), &[1]);
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (1, 1)
    );
    let mut wrong = Session::default();
    wrong.begin(&[0], &[1], 0).unwrap();
    send(&mut wrong, 0);
    assert_eq!(
        wrong.receive(&frame(1, false, &[1]), 1),
        Err(E::SequenceRejected)
    );
}

#[test]
fn positive_r_block_is_not_an_instruction_to_resend() {
    let mut session = Session::default();
    session.begin(&[0], &[1], 0).unwrap();
    send(&mut session, 0);
    assert_eq!(
        session.receive(&[0, 0x90, 0, 0x90], 1),
        Err(E::UnexpectedRBlock)
    );
    assert_eq!(session.exchanges(), 1);
    assert_eq!(session.next_block(2), Err(E::UnexpectedRBlock));
}

#[test]
fn zero_length_chaining_reaches_exact_exchange_limit() {
    let mut session = Session::default();
    session.begin(&[0], &[1], 0).unwrap();
    for index in 0..16 {
        send(&mut session, index);
        let result = session.receive(&frame((index & 1) as u8, true, &[]), index);
        if index == 15 {
            assert_eq!(result, Err(E::ExchangeLimitExceeded));
        } else {
            result.unwrap();
        }
    }
    assert_eq!(session.exchanges(), 16);
    assert_eq!(session.next_block(16), Err(E::ExchangeLimitExceeded));
    assert_eq!(session.completed_apdus(), 0);
}

#[test]
fn sixteenth_exchange_may_complete_but_no_seventeenth_is_sent() {
    let mut session = Session::default();
    session.begin(&[0], &[1], 0).unwrap();
    for index in 0..16 {
        send(&mut session, index);
        session
            .receive(
                &frame(
                    (index & 1) as u8,
                    index < 15,
                    if index < 15 { &[] } else { &[1] },
                ),
                index,
            )
            .unwrap();
    }
    assert_eq!(session.phase(), Phase::Complete);
    assert_eq!(session.exchanges(), 16);
}

#[test]
fn deadline_covers_ready_writing_receiving_and_interblock_work() {
    for stage in 0..3 {
        let mut session = Session::default();
        session.begin(&[0], &[1], 100).unwrap();
        if stage >= 1 {
            session.next_block(100).unwrap();
        }
        if stage == 2 {
            session.written(5, 100).unwrap();
        }
        assert_eq!(session.tick(30_099), Ok(()));
        assert_eq!(session.tick(30_100), Err(E::DeadlineExceeded));
    }
    let mut session = Session::default();
    session.begin(&[0], &[1, 2], 0).unwrap();
    send(&mut session, 0);
    session.receive(&frame(0, true, &[1]), 29_999).unwrap();
    assert_eq!(session.next_block(30_000), Err(E::DeadlineExceeded));
}

#[test]
fn full_late_write_is_counted_and_then_terminates() {
    let mut session = Session::default();
    session.begin(&[0], &[1], 0).unwrap();
    let block = session.next_block(0).unwrap();
    assert_eq!(
        session.written(block.as_bytes().len(), 30_000),
        Err(E::DeadlineExceeded)
    );
    assert_eq!(session.exchanges(), 1);
}

#[test]
fn clock_regression_is_sticky_and_large_clocks_do_not_overflow() {
    let mut session = Session::default();
    session.begin(&[0], &[1], u64::MAX - 3).unwrap();
    let block = session.next_block(u64::MAX - 2).unwrap();
    session
        .written(block.as_bytes().len(), u64::MAX - 1)
        .unwrap();
    session.receive(&frame(0, false, &[1]), u64::MAX).unwrap();
    assert_eq!(session.tick(0), Err(E::ClockRegression));
    assert_eq!(session.begin(&[], &[], 0), Err(E::ClockRegression));
}

#[test]
fn state_and_partial_write_failures_cannot_be_recovered() {
    let mut session = Session::default();
    assert_eq!(session.next_block(0), Err(E::StateRejected));
    assert_eq!(session.begin(&[0], &[1], 0), Err(E::StateRejected));
    let mut partial = Session::default();
    partial.begin(&[0], &[1], 0).unwrap();
    let block = partial.next_block(0).unwrap();
    assert_eq!(
        partial.written(block.as_bytes().len() - 1, 0),
        Err(E::PartialWrite)
    );
    assert_eq!(
        partial.written(block.as_bytes().len(), 0),
        Err(E::PartialWrite)
    );
    assert_eq!(partial.exchanges(), 0);
}

#[test]
fn oversized_expected_or_command_is_rejected_before_storage() {
    let mut session = Session::default();
    assert_eq!(
        session.begin(&[0], &[0; 219], 0),
        Err(E::ResponseLengthRejected)
    );
    let mut session = Session::default();
    assert_eq!(
        session.begin(&[0; 31], &[0], 0),
        Err(E::CommandLengthRejected)
    );
}

fn control(nad: u8, pcb: u8, inf: &[u8]) -> Vec<u8> {
    let mut bytes = vec![nad, pcb, inf.len() as u8];
    bytes.extend_from_slice(inf);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

fn awaiting_ifs(now: u64) -> Session {
    let mut session = Session::with_ifs();
    assert_eq!(session.receive_bound(), 36);
    assert!(!session.ifs_accepted());
    session.begin_ifs(now).unwrap();
    assert_eq!(send(&mut session, now), [0, 0xc1, 1, 0xfe, 0x3e]);
    assert_eq!(session.receive_bound(), 36);
    session
}

fn accepted_ifs() -> Session {
    let mut session = awaiting_ifs(0);
    session.receive(&control(0, 0xe1, &[0xfe]), 1).unwrap();
    assert!(session.ifs_accepted());
    assert_eq!(session.receive_bound(), 258);
    session
}

fn assert_first_failure(session: &mut Session, expected: E) {
    let state = (
        session.send_sequence(),
        session.receive_sequence(),
        session.completed_apdus(),
        session.exchanges(),
        session.receive_bound(),
        session.response_prefix().to_vec(),
    );
    assert_eq!(session.phase(), Phase::Failed);
    assert_eq!(session.failure(), Some(expected));
    assert_eq!(session.tick(u64::MAX), Err(expected));
    assert_eq!(session.begin_ifs(0), Err(expected));
    assert_eq!(session.begin(&[], &[], 0), Err(expected));
    assert_eq!(session.next_block(0), Err(expected));
    assert_eq!(session.written(5, 0), Err(expected));
    assert_eq!(
        session.receive(&control(0, 0xe1, &[0xfe]), 0),
        Err(expected)
    );
    assert_eq!(
        (
            session.send_sequence(),
            session.receive_sequence(),
            session.completed_apdus(),
            session.exchanges(),
            session.receive_bound(),
            session.response_prefix().to_vec(),
        ),
        state
    );
}

#[test]
fn exact_ifs_changes_only_negotiation_state_and_receive_bound() {
    let mut session = accepted_ifs();
    assert_eq!(session.phase(), Phase::Idle);
    assert_eq!(session.completed_apdus(), 0);
    assert_eq!(session.exchanges(), 1);
    assert!(session.response_prefix().is_empty());
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (0, 0)
    );
    session.begin(&[0xaa; 30], &[0x55; 218], 1).unwrap();
    assert_eq!(session.exchanges(), 0);
    let request = send(&mut session, 1);
    assert_eq!(request.len(), 34);
    assert_eq!(request[1], 0);
    session.receive(&frame(0, false, &[0x55; 218]), 2).unwrap();
    assert_eq!(session.phase(), Phase::Complete);
    assert_eq!(session.completed_apdus(), 1);
    assert_eq!(session.exchanges(), 1);
    assert_eq!(
        (session.send_sequence(), session.receive_sequence()),
        (1, 1)
    );
    assert_eq!(session.response_prefix(), &[0x55; 218]);
    assert_eq!(Session::default().receive_bound(), 36);
}

#[test]
fn only_the_exact_ifs_echo_can_activate_ifsd() {
    for inf in 0..=255 {
        let mut session = awaiting_ifs(0);
        let result = session.receive(&control(0, 0xe1, &[inf]), 1);
        if inf == 0xfe {
            assert_eq!(result, Ok(()));
            assert_eq!(session.receive_bound(), 258);
        } else {
            assert_eq!(result, Err(E::IfsRejected));
            assert!(!session.ifs_accepted());
            assert_eq!(session.receive_bound(), 36);
            assert_first_failure(&mut session, E::IfsRejected);
        }
    }
}

#[test]
fn malformed_echo_and_block_substitutions_fail_by_name() {
    let mut bad_len = control(0, 0xe1, &[0xfe]);
    bad_len[2] = 2;
    let mut bad_lrc = control(0, 0xe1, &[0xfe]);
    bad_lrc[4] ^= 1;
    let cases = [
        (bad_len, E::BlockLengthRejected),
        (bad_lrc, E::ChecksumRejected),
        (control(1, 0xe1, &[0xfe]), E::NadRejected),
        (control(0, 0xe5, &[0xfe]), E::PcbRejected),
        (control(0, 0xe1, &[]), E::ControlLengthRejected),
        (control(0, 0xe1, &[0xfe, 0xfe]), E::ControlLengthRejected),
        (control(0, 0xc1, &[0xfe]), E::IfsRejected),
        (frame(0, false, &[0xfe]), E::IfsRejected),
        (frame(1, true, &[0xfe]), E::IfsRejected),
        (control(0, 0x80, &[]), E::UnexpectedRBlock),
        (control(0, 0x90, &[]), E::UnexpectedRBlock),
        (control(0, 0x81, &[]), E::RetransmissionRejected),
        (control(0, 0xc3, &[1]), E::WtxRejected),
        (control(0, 0xe3, &[1]), E::WtxRejected),
        (control(0, 0xc0, &[]), E::ResynchRejected),
        (control(0, 0xe0, &[]), E::ResynchRejected),
        (control(0, 0xc2, &[]), E::AbortRejected),
        (control(0, 0xe2, &[]), E::AbortRejected),
    ];
    for (bytes, error) in cases {
        let mut session = awaiting_ifs(0);
        assert_eq!(session.receive(&bytes, 1), Err(error), "{bytes:02x?}");
        assert_eq!(session.receive_bound(), 36);
        assert!(!session.ifs_accepted());
        assert_eq!(
            (session.send_sequence(), session.receive_sequence()),
            (0, 0)
        );
        assert_eq!(session.completed_apdus(), 0);
        assert!(session.response_prefix().is_empty());
        assert_first_failure(&mut session, error);
    }
}

#[test]
fn every_single_bit_echo_corruption_fails_without_activating_ifsd() {
    let echo = control(0, 0xe1, &[0xfe]);
    for index in 0..echo.len() {
        for bit in 0..8 {
            let mut session = awaiting_ifs(0);
            let mut bytes = echo.clone();
            bytes[index] ^= 1 << bit;
            assert!(session.receive(&bytes, 1).is_err());
            assert!(!session.ifs_accepted());
            assert_eq!(session.receive_bound(), 36);
        }
    }
}

#[test]
fn receive_bound_changes_only_after_acceptance_and_remains_distinct_from_apdu_bound() {
    let maximum = frame(0, false, &[0x55; 254]);
    assert_eq!(maximum.len(), 258);
    let mut session = awaiting_ifs(0);
    assert_eq!(session.receive(&maximum, 1), Err(E::BlockLengthRejected));
    assert_eq!(session.receive_bound(), 36);
    assert_first_failure(&mut session, E::BlockLengthRejected);

    let mut default = Session::default();
    default.begin(&[0], &[0x55; 218], 0).unwrap();
    send(&mut default, 0);
    assert_eq!(default.receive(&maximum, 1), Err(E::BlockLengthRejected));

    let mut session = accepted_ifs();
    session.begin(&[0], &[0x55; 218], 1).unwrap();
    send(&mut session, 1);
    // The complete 258-byte TPDU is valid, but 254 application bytes exceed
    // this readback's independent expected-response ceiling of 218.
    assert_eq!(session.receive(&maximum, 2), Err(E::ResponseLengthRejected));
    assert!(session.ifs_accepted());
    assert_eq!(session.receive_bound(), 258);
    assert_first_failure(&mut session, E::ResponseLengthRejected);

    let mut session = accepted_ifs();
    session.begin(&[0], &[0x55; 218], 1).unwrap();
    send(&mut session, 1);
    assert_eq!(
        session.receive(&frame(0, false, &[0x55; 255]), 2),
        Err(E::BlockLengthRejected)
    );
    assert_first_failure(&mut session, E::BlockLengthRejected);
}

#[test]
fn ifs_negotiation_is_required_once_and_only_before_any_apdu() {
    let mut required = Session::with_ifs();
    assert_eq!(required.begin(&[0], &[1], 0), Err(E::StateRejected));
    assert_first_failure(&mut required, E::StateRejected);
    for stage in 0..3 {
        let mut session = Session::with_ifs();
        session.begin_ifs(0).unwrap();
        if stage >= 1 {
            session.next_block(0).unwrap();
        }
        if stage == 2 {
            session.written(5, 0).unwrap();
        }
        assert_eq!(session.begin(&[0], &[1], 0), Err(E::StateRejected));
        assert_first_failure(&mut session, E::StateRejected);
    }
    for stage in 0..6 {
        let mut session = Session::with_ifs();
        session.begin_ifs(0).unwrap();
        if stage >= 1 {
            session.next_block(0).unwrap();
        }
        if stage >= 2 {
            session.written(5, 0).unwrap();
        }
        if stage >= 3 {
            session.receive(&control(0, 0xe1, &[0xfe]), 1).unwrap();
        }
        if stage >= 4 {
            session.begin(&[0], &[1], 1).unwrap();
        }
        if stage == 5 {
            send(&mut session, 1);
            session.receive(&frame(0, false, &[1]), 2).unwrap();
        }
        assert_eq!(session.begin_ifs(2), Err(E::StateRejected));
        assert_first_failure(&mut session, E::StateRejected);
    }
    for stage in 0..3 {
        let mut session = Session::default();
        if stage >= 1 {
            session.begin(&[0], &[1], 0).unwrap();
        }
        if stage == 2 {
            send(&mut session, 0);
            session.receive(&frame(0, false, &[1]), 1).unwrap();
        }
        assert_eq!(session.begin_ifs(1), Err(E::StateRejected));
        assert_eq!(session.receive_bound(), 36);
        assert_first_failure(&mut session, E::StateRejected);
    }
}

#[test]
fn unsolicited_repeated_and_card_originated_ifs_are_never_accepted() {
    for pcb in [0xc1, 0xe1] {
        for stage in 0..7 {
            let mut session = if stage < 3 {
                Session::with_ifs()
            } else {
                accepted_ifs()
            };
            if stage == 1 || stage == 2 {
                session.begin_ifs(0).unwrap();
            }
            if stage == 2 {
                session.next_block(0).unwrap();
            }
            if stage >= 4 {
                session.begin(&[0], &[1], 1).unwrap();
            }
            if stage >= 5 {
                send(&mut session, 1);
            }
            if stage == 6 {
                session.receive(&frame(0, false, &[1]), 2).unwrap();
            }
            assert_eq!(
                session.receive(&control(0, pcb, &[0xfe]), 2),
                Err(E::IfsRejected),
                "PCB {pcb:02x}, stage {stage}"
            );
            assert_first_failure(&mut session, E::IfsRejected);
        }
        let mut session = Session::default();
        session.begin(&[0], &[1], 0).unwrap();
        send(&mut session, 0);
        assert_eq!(
            session.receive(&control(0, pcb, &[0xfe]), 1),
            Err(E::IfsRejected)
        );
    }
}

#[test]
fn ifs_deadline_covers_ready_writing_receiving_and_observation_work() {
    assert_eq!(IFS_BUDGET_MS, 5_000);
    for stage in 0..3 {
        let mut session = Session::with_ifs();
        session.begin_ifs(100).unwrap();
        if stage >= 1 {
            session.next_block(100).unwrap();
        }
        if stage == 2 {
            session.written(5, 100).unwrap();
        }
        assert_eq!(session.tick(5_099), Ok(()));
        assert_eq!(session.tick(5_100), Err(E::DeadlineExceeded));
        assert_eq!(session.receive_bound(), 36);
        assert_first_failure(&mut session, E::DeadlineExceeded);
    }
    let mut on_time = awaiting_ifs(0);
    on_time.receive(&control(0, 0xe1, &[0xfe]), 4_999).unwrap();
    let mut late = awaiting_ifs(0);
    late.tick(4_999).unwrap();
    assert_eq!(
        late.receive(&control(0, 0xe1, &[0xfe]), 5_000),
        Err(E::DeadlineExceeded)
    );
    assert_first_failure(&mut late, E::DeadlineExceeded);

    let mut late_write = Session::with_ifs();
    late_write.begin_ifs(0).unwrap();
    late_write.next_block(0).unwrap();
    assert_eq!(late_write.written(5, 5_000), Err(E::DeadlineExceeded));
    assert_eq!(late_write.exchanges(), 1);
    assert_first_failure(&mut late_write, E::DeadlineExceeded);
}

#[test]
fn ifs_partial_writes_and_duplicate_claims_are_terminal() {
    for count in [0, 1, 4, 6, usize::MAX] {
        let mut session = Session::with_ifs();
        session.begin_ifs(0).unwrap();
        session.next_block(0).unwrap();
        assert_eq!(session.written(count, 0), Err(E::PartialWrite));
        assert_eq!(session.exchanges(), 0);
        assert_eq!(session.receive_bound(), 36);
        assert_first_failure(&mut session, E::PartialWrite);
    }
    let mut duplicate = Session::with_ifs();
    duplicate.begin_ifs(0).unwrap();
    duplicate.next_block(0).unwrap();
    assert_eq!(duplicate.next_block(0), Err(E::StateRejected));
    assert_first_failure(&mut duplicate, E::StateRejected);
    let mut written = awaiting_ifs(0);
    assert_eq!(written.written(5, 0), Err(E::StateRejected));
    assert_first_failure(&mut written, E::StateRejected);
}

#[test]
fn ifs_requires_one_complete_tpdu_and_never_reassembles_fragments() {
    let echo = control(0, 0xe1, &[0xfe]);
    for split in 0..echo.len() {
        let mut session = awaiting_ifs(0);
        assert_eq!(
            session.receive(&echo[..split], 1),
            Err(E::BlockLengthRejected)
        );
        assert_eq!(
            session.receive(&echo[split..], 1),
            Err(E::BlockLengthRejected)
        );
        assert_first_failure(&mut session, E::BlockLengthRejected);
    }
    let mut coalesced = awaiting_ifs(0);
    assert_eq!(
        coalesced.receive(&[echo.clone(), echo].concat(), 1),
        Err(E::BlockLengthRejected)
    );
    assert_first_failure(&mut coalesced, E::BlockLengthRejected);
}

#[test]
fn ifs_clock_regression_is_terminal_and_large_monotonic_clocks_work() {
    let mut session = awaiting_ifs(u64::MAX - 1);
    session
        .receive(&control(0, 0xe1, &[0xfe]), u64::MAX)
        .unwrap();
    assert_eq!(session.receive_bound(), 258);
    assert_eq!(session.tick(0), Err(E::ClockRegression));
    assert_first_failure(&mut session, E::ClockRegression);
    let mut session = awaiting_ifs(100);
    assert_eq!(
        session.receive(&control(0, 0xe1, &[0xfe]), 99),
        Err(E::ClockRegression)
    );
    assert_eq!(session.receive_bound(), 36);
    assert_first_failure(&mut session, E::ClockRegression);
}

#[test]
fn negotiated_frozen_readbacks_allow_both_unchained_and_valid_chained_responses() {
    for chunk_size in [218, 109, 32] {
        let mut session = accepted_ifs();
        let mut now = 1;
        let mut total_exchanges = 0;
        let fixture = include_str!(
            "../../../bench/card-enrollment/tests/fixtures/sitting_committed_readback_v1.tsv"
        );
        for line in fixture.lines().skip(5) {
            let fields: Vec<_> = line.split('\t').collect();
            let command = hex(fields[3]);
            let expected = hex(fields[4]);
            let command_sequence = session.send_sequence();
            session.begin(&command, &expected, now).unwrap();
            for (index, chunk) in expected.chunks(chunk_size).enumerate() {
                let receive_sequence = session.receive_sequence();
                let request = send(&mut session, now);
                assert!(request.len() <= 34);
                assert_eq!(
                    request[1],
                    if index == 0 {
                        command_sequence << 6
                    } else {
                        0x80 | receive_sequence << 4
                    }
                );
                now += 1;
                session
                    .receive(
                        &frame(
                            receive_sequence,
                            (index + 1) * chunk_size < expected.len(),
                            chunk,
                        ),
                        now,
                    )
                    .unwrap();
            }
            assert_eq!(session.phase(), Phase::Complete);
            assert_eq!(session.response_prefix(), expected);
            assert_eq!(session.send_sequence(), command_sequence ^ 1);
            total_exchanges += session.exchanges();
        }
        assert_eq!(session.completed_apdus(), 8);
        assert_eq!(session.receive_bound(), 258);
        assert_eq!(session.send_sequence(), 0);
        if chunk_size == 218 {
            assert_eq!(total_exchanges, 8);
            assert_eq!(session.receive_sequence(), 0);
        } else if chunk_size == 32 {
            assert_eq!(total_exchanges, 33);
            assert_eq!(session.receive_sequence(), 1);
        }
        assert_eq!(
            session.begin(&[0], &[0x90, 0], now),
            Err(E::ApduLimitExceeded)
        );
    }
}

#[test]
fn negotiated_chaining_retains_prefix_sequence_and_exchange_limits() {
    let mut wrong_prefix = accepted_ifs();
    wrong_prefix.begin(&[0], &[0x55; 218], 1).unwrap();
    send(&mut wrong_prefix, 1);
    assert_eq!(
        wrong_prefix.receive(&frame(0, true, &[0x56; 109]), 2),
        Err(E::ResponseMismatch)
    );
    assert!(wrong_prefix.response_prefix().is_empty());
    assert_first_failure(&mut wrong_prefix, E::ResponseMismatch);

    let mut duplicate = accepted_ifs();
    duplicate.begin(&[0], &[0x55; 218], 1).unwrap();
    send(&mut duplicate, 1);
    duplicate.receive(&frame(0, true, &[0x55; 109]), 2).unwrap();
    send(&mut duplicate, 2);
    assert_eq!(
        duplicate.receive(&frame(0, false, &[0x55; 109]), 3),
        Err(E::SequenceRejected)
    );
    assert_eq!(duplicate.response_prefix(), &[0x55; 109]);
    assert_first_failure(&mut duplicate, E::SequenceRejected);

    for complete in [false, true] {
        let mut session = accepted_ifs();
        session.begin(&[0], &[1], 1).unwrap();
        for index in 0..16 {
            send(&mut session, index + 1);
            let last = complete && index == 15;
            let result = session.receive(
                &frame((index & 1) as u8, !last, if last { &[1] } else { &[] }),
                index + 1,
            );
            if index == 15 && !complete {
                assert_eq!(result, Err(E::ExchangeLimitExceeded));
            } else {
                result.unwrap();
            }
        }
        assert_eq!(session.exchanges(), 16);
        if complete {
            assert_eq!(session.completed_apdus(), 1);
        } else {
            assert_first_failure(&mut session, E::ExchangeLimitExceeded);
        }
    }
}
