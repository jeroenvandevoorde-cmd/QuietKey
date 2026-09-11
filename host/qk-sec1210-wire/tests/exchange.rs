use qk_sec1210_wire::{Command, Error, Exchange, Observation, Phase, REGISTERED_ATR};

fn frame(kind: u8, seq: u8, status: u8, error: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![3, 6, kind];
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(&[0, seq, status, error, parameter]);
    b.extend_from_slice(payload);
    b.push(b.iter().fold(0, |a, b| a ^ b));
    b
}
fn status() -> Vec<u8> {
    frame(0x81, 1, 1, 0, 0, &[])
}
fn atr() -> Vec<u8> {
    frame(0x80, 2, 0, 0, 0, &REGISTERED_ATR)
}
fn started() -> Exchange {
    let mut x = Exchange::default();
    assert_eq!(x.begin(), Ok(Command::GetSlotStatus));
    x.written(13).unwrap();
    x
}
fn power() -> Exchange {
    let mut x = started();
    x.receive(&status(), 10).unwrap();
    assert_eq!(x.begin(), Ok(Command::PowerOn));
    x.written(13).unwrap();
    x
}

#[test]
fn two_commands_only_with_exact_status_and_atr() {
    let mut x = started();
    assert_eq!(
        x.receive(&status(), 10).unwrap(),
        vec![Observation::SlotStatus {
            status: 1,
            error: 0,
            clock: 0
        }]
    );
    assert_eq!(x.phase(), Phase::ReadyPower);
    x.begin().unwrap();
    x.written(13).unwrap();
    assert_eq!(
        x.receive(&atr(), 10).unwrap(),
        vec![Observation::Atr(REGISTERED_ATR)]
    );
    assert_eq!(x.phase(), Phase::Complete);
    assert_eq!((x.requests(), x.responses()), (2, 2));
    assert_eq!(x.begin(), Err(Error::SequenceViolation));
}
#[test]
fn response_acceptance_is_invariant_under_every_split() {
    for cut in 0..=atr().len() {
        let mut x = power();
        let b = atr();
        x.receive(&b[..cut], 10).unwrap();
        if cut < b.len() {
            x.receive(&b[cut..], 11).unwrap();
        }
        assert_eq!(x.phase(), Phase::Complete);
    }
}
#[test]
fn coalesced_events_then_response_and_fragmented_event() {
    let mut x = started();
    x.receive(&[0x50], 10).unwrap();
    let mut bytes = vec![0x0d, 0x50, 3];
    bytes.extend(status());
    let observations = x.receive(&bytes, 11).unwrap();
    assert_eq!(
        observations[0],
        Observation::SlotChange {
            bitmap: 13,
            slot1_bits: 3
        }
    );
    assert_eq!(x.events(), 2);
    assert_eq!(x.responses(), 1);
}
#[test]
fn every_clock_byte_is_recorded_not_an_acceptance_gate() {
    for clock in 0..=255 {
        let mut x = started();
        assert_eq!(
            x.receive(&frame(0x81, 1, 1, 0, clock, &[]), 10).unwrap()[0],
            Observation::SlotStatus {
                status: 1,
                error: 0,
                clock
            }
        );
    }
}
#[test]
fn status_matrix_rejects_active_absent_reserved_failed_and_time_extension() {
    for (status, error) in [
        (0, Error::AlreadyActive),
        (2, Error::CardAbsent),
        (3, Error::StatusReserved),
        (5, Error::StatusReserved),
        (0x41, Error::CommandFailed),
        (0x81, Error::TimeExtensionRejected),
        (0xc1, Error::StatusReserved),
    ] {
        assert_eq!(
            started().receive(&frame(0x81, 1, status, 0, 0, &[]), 10),
            Err(error)
        );
    }
    assert_eq!(
        started().receive(&frame(0x81, 1, 1, 1, 0, &[]), 10),
        Err(Error::StatusErrorRejected)
    );
    assert_eq!(
        started().receive(&frame(0x81, 1, 1, 0, 0, &[1]), 10),
        Err(Error::PayloadRejected)
    );
}
#[test]
fn wrong_slot_sequence_type_precede_status() {
    let mut b = status();
    b[7] = 1;
    b[12] ^= 1;
    assert_eq!(started().receive(&b, 10), Err(Error::SlotRejected));
    assert_eq!(
        started().receive(&frame(0x81, 2, 0xff, 0, 0, &[]), 10),
        Err(Error::SequenceRejected)
    );
    assert_eq!(
        started().receive(&frame(0x80, 1, 0xff, 0, 0, &[]), 10),
        Err(Error::ResponseTypeRejected)
    );
}
#[test]
fn power_requires_active_unchained_exact_atr() {
    assert_eq!(
        power().receive(&frame(0x80, 2, 1, 0, 0, &REGISTERED_ATR), 10),
        Err(Error::IccStatusRejected)
    );
    assert_eq!(
        power().receive(&frame(0x80, 2, 0, 0, 1, &REGISTERED_ATR), 10),
        Err(Error::ChainingRejected)
    );
    for len in [0, 14, 16, 33, 34, 261] {
        assert_eq!(
            power().receive(&frame(0x80, 2, 0, 0, 0, &vec![0; len]), 10),
            Err(Error::AtrRejected)
        );
    }
}
#[test]
fn event_bitmap_hardware_faults_and_event_cap_terminate() {
    for bitmap in [0, 2, 4, 6, 8, 10, 12, 14] {
        assert_eq!(
            started().receive(&[0x50, bitmap], 10),
            Err(Error::CardAbsent)
        );
    }
    assert_eq!(
        started().receive(&[0x50, 0x13], 10),
        Err(Error::EventBitmapRejected)
    );
    assert_eq!(
        started().receive(&[0x51, 0, 1, 1], 10),
        Err(Error::HardwareError)
    );
    assert_eq!(
        started().receive(&[0x51, 1, 1, 1], 10),
        Err(Error::SlotRejected)
    );
    assert_eq!(
        started().receive(&[0x51, 0, 2, 1], 10),
        Err(Error::SequenceRejected)
    );
    let mut x = started();
    x.receive(&[0x50, 3].repeat(64), 10).unwrap();
    assert_eq!(x.receive(&[0x50, 3], 11), Err(Error::EventLimitExceeded));
}
#[test]
fn absolute_deadline_includes_idle_reads_events_and_partial_frames() {
    let mut x = started();
    x.receive(&[], 4999).unwrap();
    assert_eq!(x.receive(&status(), 5000), Err(Error::DeadlineExceeded));
    let mut x = started();
    x.receive(&[0x50, 3], 4900).unwrap();
    x.receive(&[3], 4999).unwrap();
    assert_eq!(x.receive(&[], 5000), Err(Error::PartialFrameDeadline));
    assert_eq!(started().receive(&[], 0), Ok(vec![]));
}
#[test]
fn partial_write_is_terminal_and_other_command_cannot_start() {
    for bytes in [0, 1, 12, 14, usize::MAX] {
        let mut x = Exchange::default();
        x.begin().unwrap();
        assert_eq!(x.written(bytes), Err(Error::PartialWrite));
        assert_eq!(x.begin(), Err(Error::PartialWrite));
    }
}
#[test]
fn receive_cap_unsolicited_and_trailing_data_are_named() {
    assert_eq!(
        started().receive(&[0; 4097], 10),
        Err(Error::ReceiveLimitExceeded)
    );
    assert_eq!(
        Exchange::default().receive(&status(), 10),
        Err(Error::UnsolicitedResponse)
    );
    let mut bytes = status();
    bytes.extend(atr());
    assert_eq!(started().receive(&bytes, 10), Err(Error::TrailingData));
}
#[test]
fn time_cannot_move_backwards_and_failure_is_sticky() {
    let mut x = started();
    x.receive(&[], 2).unwrap();
    assert_eq!(x.receive(&[], 1), Err(Error::ClockRegression));
    assert_eq!(x.receive(&status(), 3), Err(Error::ClockRegression));
}

#[test]
fn event_facts_survive_coalesced_rejection_and_hardware_failure() {
    let mut x = started();
    assert_eq!(x.receive(&[0x50, 3, 0], 10), Err(Error::PrefixRejected));
    assert_eq!(
        x.observations(),
        &[Observation::SlotChange {
            bitmap: 3,
            slot1_bits: 0
        }]
    );
    let mut x = started();
    assert_eq!(x.receive(&[0x51, 0, 1, 1], 10), Err(Error::HardwareError));
    assert_eq!(
        x.observations(),
        &[Observation::HardwareError {
            slot: 0,
            sequence: 1,
            code: 1
        }]
    );
}

#[test]
fn event_budget_is_shared_across_commands() {
    let mut x = started();
    let mut b = [0x50, 3].repeat(32);
    b.extend(status());
    x.receive(&b, 10).unwrap();
    x.begin().unwrap();
    x.written(13).unwrap();
    x.receive(&[0x50, 3].repeat(32), 10).unwrap();
    assert_eq!(x.receive(&[0x50, 3], 11), Err(Error::EventLimitExceeded));
    assert_eq!(x.observations().len(), 65);
}
