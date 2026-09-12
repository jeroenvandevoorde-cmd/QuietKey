use qk_sec1210_wire::{
    Error as W, ReadbackCommand as C, ReadbackError as E, ReadbackObservation as O,
    ReadbackPhase as P, ReadbackSession as S, REGISTERED_ATR,
};

const PARAMETERS: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 3, 0xfe, 0];
const TPDU: [u8; 5] = [0, 0, 1, 0, 1];

fn response(
    kind: u8,
    slot: u8,
    sequence: u8,
    status: u8,
    error: u8,
    parameter: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![3, 6, kind];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[slot, sequence, status, error, parameter]);
    bytes.extend_from_slice(payload);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}
fn initial_response(command: C) -> Vec<u8> {
    match command {
        C::GetSlotStatus => response(0x81, 0, 1, 1, 0, 0xff, &[]),
        C::PowerOn => response(0x80, 0, 2, 0, 0, 0, &REGISTERED_ATR),
        C::GetParameters => response(0x82, 0, 3, 0, 0, 1, &PARAMETERS),
        C::XfrBlock => panic!("not an initialization response"),
    }
}
fn init_to_parameters() -> S {
    let mut session = S::default();
    for command in [C::GetSlotStatus, C::PowerOn] {
        let request = session.begin_initial(0).unwrap();
        assert_eq!(request.command(), command);
        session.written(request.as_bytes().len(), 0).unwrap();
        session.receive(&initial_response(command), 0).unwrap();
    }
    let request = session.begin_initial(0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    session
}
fn initialized() -> S {
    let mut session = init_to_parameters();
    session
        .receive(&initial_response(C::GetParameters), 0)
        .unwrap();
    session
}
fn pending_transfer() -> S {
    let mut session = initialized();
    let request = session.begin_transfer(&TPDU, 0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    session
}

#[test]
fn initialization_vectors_and_returned_parameters_are_exact() {
    let mut session = S::default();
    let expected = [
        vec![3, 6, 0x65, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x61],
        vec![3, 6, 0x62, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0x67],
        vec![3, 6, 0x6c, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0x6a],
    ];
    for (index, command) in [C::GetSlotStatus, C::PowerOn, C::GetParameters]
        .into_iter()
        .enumerate()
    {
        let request = session.begin_initial(index as u64 * 20).unwrap();
        assert_eq!(request.command(), command);
        assert_eq!(request.as_bytes(), expected[index]);
        session
            .written(request.as_bytes().len(), index as u64 * 20)
            .unwrap();
        session
            .receive(&initial_response(command), index as u64 * 20 + 10)
            .unwrap();
    }
    assert_eq!(session.phase(), P::ReadyTransfer);
    assert_eq!(
        (
            session.requests(),
            session.responses(),
            session.received_bytes()
        ),
        (3, 3, 61)
    );
    assert_eq!(
        session.observations(),
        &[
            O::SlotStatus {
                status: 1,
                error: 0,
                clock: 0xff
            },
            O::Atr(REGISTERED_ATR),
            O::Parameters {
                protocol: 1,
                bytes: PARAMETERS
            },
        ]
    );
}

#[test]
fn parameters_gate_only_protocol_ifsc_and_lrc_bit() {
    for index in [0, 1, 2, 3, 4, 6] {
        for value in 0..=255u8 {
            if index == 1 && value & 1 != 0 {
                continue;
            }
            let mut params = PARAMETERS;
            params[index] = value;
            let mut session = init_to_parameters();
            session
                .receive(&response(0x82, 0, 3, 0, 0, 1, &params), 1)
                .unwrap();
            assert_eq!(
                session.observations().last(),
                Some(&O::Parameters {
                    protocol: 1,
                    bytes: params
                })
            );
        }
    }
}

#[test]
fn rejected_parameters_remain_observable() {
    for (protocol, params, error) in [
        (0, PARAMETERS, E::ProtocolRejected),
        (1, [0x18, 0x10, 0, 0, 0, 0xfd, 0], E::IfscRejected),
        (1, [0x18, 0x11, 0, 0, 0, 0xfe, 0], E::LrcModeRejected),
    ] {
        let mut session = init_to_parameters();
        assert_eq!(
            session.receive(&response(0x82, 0, 3, 0, 0, protocol, &params), 1),
            Err(error)
        );
        assert_eq!(session.responses(), 2);
        assert_eq!(
            session.observations().last(),
            Some(&O::Parameters {
                protocol,
                bytes: params
            })
        );
        assert_eq!(session.begin_transfer(&TPDU, 1), Err(error));
    }
    let mut session = init_to_parameters();
    assert_eq!(
        session.receive(&response(0x82, 0, 3, 0, 0, 1, &[0; 6]), 1),
        Err(E::Wire(W::PayloadRejected))
    );
}

#[test]
fn xfrblock_has_zero_bwi_and_level_parameter_and_carries_one_tpdu() {
    let mut session = initialized();
    let request = session.begin_transfer(&TPDU, 1).unwrap();
    assert_eq!(request.command(), C::XfrBlock);
    assert_eq!(request.sequence(), 4);
    assert_eq!(
        &request.as_bytes()[..12],
        &[3, 6, 0x6f, 5, 0, 0, 0, 0, 4, 0, 0, 0]
    );
    assert_eq!(&request.as_bytes()[12..17], &TPDU);
    assert_eq!(request.as_bytes().iter().fold(0, |sum, byte| sum ^ byte), 0);
    session.written(request.as_bytes().len(), 1).unwrap();
    let received_tpdu = [0, 0, 2, 0x90, 0, 0x92];
    session
        .receive(&response(0x80, 0, 4, 0, 0, 0, &received_tpdu), 2)
        .unwrap();
    assert_eq!(session.response().unwrap().payload(), received_tpdu);
    assert_eq!(
        session.observations().last(),
        Some(&O::Transfer {
            sequence: 4,
            payload_bytes: 6
        })
    );
}

#[test]
fn time_extension_precedes_expected_type_and_error() {
    for kind in [0x80, 0x81, 0x82] {
        let mut session = pending_transfer();
        assert_eq!(
            session.receive(&response(kind, 0, 4, 0x80, 0xff, 0, &[]), 1),
            Err(E::Wire(W::TimeExtensionRejected))
        );
        assert_eq!(session.responses(), 3);
    }
    for (slot, seq, status, error) in [
        (1, 4, 0x80, W::SlotRejected),
        (0, 3, 0x80, W::SequenceRejected),
        (0, 4, 0x84, W::StatusReserved),
    ] {
        let mut session = pending_transfer();
        assert_eq!(
            session.receive(&response(0x81, slot, seq, status, 1, 0, &[]), 1),
            Err(E::Wire(error))
        );
    }
}

#[test]
fn transfer_response_shape_and_status_are_fail_first() {
    for (kind, status, error, chain, expected) in [
        (0x81, 0, 0, 0, W::ResponseTypeRejected),
        (0x80, 0x40, 9, 0, W::CommandFailed),
        (0x80, 0, 9, 0, W::StatusErrorRejected),
        (0x80, 1, 0, 0, W::IccStatusRejected),
        (0x80, 2, 0, 0, W::CardAbsent),
        (0x80, 3, 0, 0, W::StatusReserved),
        (0x80, 0, 0, 1, W::ChainingRejected),
    ] {
        let mut session = pending_transfer();
        assert_eq!(
            session.receive(&response(kind, 0, 4, status, error, chain, &TPDU), 1),
            Err(E::Wire(expected))
        );
    }
}

#[test]
fn every_fragment_split_agrees_with_the_complete_frame() {
    let raw = response(0x80, 0, 4, 0, 0, 0, &TPDU);
    for split in 0..=raw.len() {
        let mut session = pending_transfer();
        session.receive(&raw[..split], 10).unwrap();
        if split != raw.len() {
            session.receive(&raw[split..], 11).unwrap();
        }
        assert_eq!(session.phase(), P::ReadyTransfer);
        assert_eq!(session.response().unwrap().payload(), TPDU);
    }
}

#[test]
fn coalesced_events_precede_response_without_stealing_its_sequence() {
    let mut session = pending_transfer();
    let mut raw = vec![0x50, 0x0f, 0x50, 0x01];
    raw.extend(response(0x80, 0, 4, 0, 0, 0, &TPDU));
    session.receive(&raw, 1).unwrap();
    assert_eq!(session.events(), 2);
    assert_eq!(session.responses(), 4);
    assert_eq!(
        &session.observations()[3..],
        &[
            O::SlotChange {
                bitmap: 0x0f,
                slot1_bits: 3
            },
            O::SlotChange {
                bitmap: 1,
                slot1_bits: 0
            },
            O::Transfer {
                sequence: 4,
                payload_bytes: 5
            },
        ]
    );
}

#[test]
fn malformed_and_absent_events_retain_their_decoded_fact() {
    for (bitmap, error) in [(0x11, W::EventBitmapRejected), (0x02, W::CardAbsent)] {
        let mut session = pending_transfer();
        assert_eq!(session.receive(&[0x50, bitmap], 1), Err(E::Wire(error)));
        assert_eq!(session.events(), 1);
        assert!(matches!(
            session.observations().last(),
            Some(O::SlotChange { .. })
        ));
    }
    for (slot, sequence, error) in [
        (1, 4, W::SlotRejected),
        (0, 3, W::SequenceRejected),
        (0, 4, W::HardwareError),
    ] {
        let mut session = pending_transfer();
        assert_eq!(
            session.receive(&[0x51, slot, sequence, 1], 1),
            Err(E::Wire(error))
        );
        assert_eq!(
            session.observations().last(),
            Some(&O::HardwareError {
                slot,
                sequence,
                code: 1
            })
        );
    }
}

#[test]
fn event_budget_is_cumulative_and_does_not_renew_deadline() {
    let mut session = pending_transfer();
    for now in 1..=64 {
        session.receive(&[0x50, 1], now).unwrap();
    }
    assert_eq!(
        session.receive(&[0x50, 1], 65),
        Err(E::Wire(W::EventLimitExceeded))
    );
    assert_eq!(session.events(), 65);
    assert_eq!(session.observations().len(), 3 + 64);
    let mut session = pending_transfer();
    session.receive(&[0x50, 1], 4999).unwrap();
    assert_eq!(
        session.receive(&[], 5000),
        Err(E::Wire(W::DeadlineExceeded))
    );
}

#[test]
fn trailing_bytes_do_not_count_a_response_but_retain_decoded_observation() {
    let mut session = pending_transfer();
    let mut raw = response(0x80, 0, 4, 0, 0, 0, &TPDU);
    raw.push(3);
    assert_eq!(session.receive(&raw, 1), Err(E::Wire(W::TrailingData)));
    assert_eq!(session.responses(), 3);
    assert!(session.response().is_none());
    assert_eq!(
        session.observations().last(),
        Some(&O::Transfer {
            sequence: 4,
            payload_bytes: 5
        })
    );
}

#[test]
fn all_128_commands_include_initialization_and_sequence_never_wraps() {
    let mut session = initialized();
    for sequence in 4..=128 {
        let request = session.begin_transfer(&TPDU, 0).unwrap();
        assert_eq!(request.sequence(), sequence);
        session.written(request.as_bytes().len(), 0).unwrap();
        session
            .receive(&response(0x80, 0, sequence, 0, 0, 0, &TPDU), 0)
            .unwrap();
    }
    assert_eq!((session.requests(), session.responses()), (128, 128));
    assert_eq!(
        session.begin_transfer(&TPDU, 0),
        Err(E::CommandLimitExceeded)
    );
    assert_eq!(session.sequence(), 128);
}

#[test]
fn received_byte_budget_is_cumulative_across_commands() {
    let mut session = initialized();
    let mut received = 61;
    for sequence in 4..=128 {
        let request = session.begin_transfer(&TPDU, 0).unwrap();
        session.written(request.as_bytes().len(), 0).unwrap();
        let raw = response(0x80, 0, sequence, 0, 0, 0, &[0; 261]);
        let result = session.receive(&raw, 0);
        if received + raw.len() > 8192 {
            assert_eq!(result, Err(E::Wire(W::ReceiveLimitExceeded)));
            assert_eq!(session.received_bytes(), received);
            return;
        }
        result.unwrap();
        received += raw.len();
        assert_eq!(session.received_bytes(), received);
    }
    panic!("receive ceiling should precede command ceiling for these frames");
}

#[test]
fn partial_frames_and_writes_have_one_terminal_failure() {
    let mut session = pending_transfer();
    session.receive(&[3, 6], 4999).unwrap();
    assert_eq!(session.tick(5000), Err(E::Wire(W::PartialFrameDeadline)));
    assert_eq!(
        session.receive(&[], 0),
        Err(E::Wire(W::PartialFrameDeadline))
    );
    let mut session = S::default();
    let request = session.begin_initial(0).unwrap();
    assert_eq!(
        session.written(request.as_bytes().len() - 1, 0),
        Err(E::Wire(W::PartialWrite))
    );
    assert_eq!(
        session.written(request.as_bytes().len(), 0),
        Err(E::Wire(W::PartialWrite))
    );
    assert_eq!(session.requests(), 0);
}

#[test]
fn clock_includes_writing_and_handles_maximum_u64() {
    let mut session = S::default();
    let request = session.begin_initial(0).unwrap();
    assert_eq!(
        session.written(request.as_bytes().len(), 5000),
        Err(E::Wire(W::DeadlineExceeded))
    );
    assert_eq!(session.requests(), 1);
    let mut session = S::default();
    let request = session.begin_initial(u64::MAX - 2).unwrap();
    session
        .written(request.as_bytes().len(), u64::MAX - 1)
        .unwrap();
    session
        .receive(&initial_response(C::GetSlotStatus), u64::MAX)
        .unwrap();
    assert_eq!(session.tick(0), Err(E::Wire(W::ClockRegression)));
}

#[test]
fn initialization_cannot_be_skipped_or_repeated() {
    let mut session = S::default();
    assert_eq!(session.begin_transfer(&TPDU, 0), Err(E::StateRejected));
    let mut session = initialized();
    assert_eq!(session.begin_initial(0), Err(E::StateRejected));
    let mut session = S::default();
    session.begin_initial(0).unwrap();
    assert_eq!(session.begin_initial(0), Err(E::StateRejected));
}

#[test]
fn wrapper_checksum_and_length_precede_all_semantic_fields() {
    let mut raw = response(0x81, 1, 9, 0x80, 1, 0, &[]);
    *raw.last_mut().unwrap() ^= 1;
    let mut session = pending_transfer();
    assert_eq!(session.receive(&raw, 1), Err(E::Wire(W::ChecksumRejected)));
    let mut session = pending_transfer();
    assert_eq!(
        session.receive(&[3, 6, 0x80, 0xff, 0xff, 0xff, 0xff], 1),
        Err(E::Wire(W::LengthExceeded))
    );
    let mut session = pending_transfer();
    assert_eq!(session.receive(&[3, 0x15, 0x16], 1), Err(E::Wire(W::Nack)));
}

#[test]
fn outgoing_transfer_is_one_bounded_complete_block() {
    for raw in [
        vec![],
        vec![0; 3],
        vec![0; 35],
        vec![0, 0, 2, 0, 0],
        vec![0, 0, 1, 0, 0],
    ] {
        let mut session = initialized();
        assert_eq!(
            session.begin_transfer(&raw, 0),
            Err(E::TransferPayloadRejected)
        );
    }
}
