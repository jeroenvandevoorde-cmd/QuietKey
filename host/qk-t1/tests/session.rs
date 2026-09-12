use qk_t1::{Error as E, Phase, Session};

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
