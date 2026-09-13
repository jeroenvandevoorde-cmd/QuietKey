use qk_sec1210_wire::{
    Error as W, ReadbackCommand as C, ReadbackError as E, ReadbackObservation as O,
    ReadbackPhase as P, ReadbackSession as S, FIDI_PARAMETERS, REGISTERED_ATR,
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
        C::SetParameters | C::XfrBlock => panic!("not an original initialization response"),
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

#[test]
fn ifs_sequence_four_vectors_are_exact_and_fragmentation_preserves_payload() {
    // Independent constants lock both XOR levels without invoking qk-t1.
    let request_tpdu = [0, 0xc1, 1, 0xfe, 0x3e];
    let response_tpdu = [0, 0xe1, 1, 0xfe, 0x1e];
    let request_frame = [
        3, 6, 0x6f, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0xc1, 1, 0xfe, 0x3e, 0x6b,
    ];
    let response_frame = [
        3, 6, 0x80, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0xe1, 1, 0xfe, 0x1e, 0x84,
    ];
    assert_eq!(
        response(0x80, 0, 4, 0, 0, 0, &response_tpdu),
        response_frame
    );
    for split in 0..=response_frame.len() {
        let mut session = initialized();
        let request = session.begin_transfer(&request_tpdu, 10).unwrap();
        assert_eq!(request.as_bytes(), request_frame);
        session.written(request_frame.len(), 10).unwrap();
        session.receive(&response_frame[..split], 11).unwrap();
        if split != response_frame.len() {
            session.receive(&response_frame[split..], 12).unwrap();
        }
        assert_eq!(session.response().unwrap().payload(), response_tpdu);
        assert_eq!((session.requests(), session.responses()), (4, 4));
        assert_eq!(session.received_bytes(), 79);
        assert_eq!(session.begin_transfer(&TPDU, 13).unwrap().sequence(), 5);
    }
}

#[test]
fn ifs_payload_is_opaque_to_transport_even_when_t1_would_reject_it() {
    // The readback transport does not negotiate IFSD or validate an S-block.
    // Wrong PCB, LEN, INF, NAD and LRC are deliberately valid CCID payloads.
    for payload in [
        [0, 0, 1, 0xfe, 0xff],
        [0, 0xe1, 2, 0xfe, 0x1d],
        [0, 0xe1, 1, 0xfd, 0x1d],
        [1, 0xe1, 1, 0xfe, 0x1f],
        [0, 0xe1, 1, 0xfe, 0x1f],
        [0, 0xc1, 1, 0xfe, 0x3e],
    ] {
        let mut session = initialized();
        let request = session
            .begin_transfer(&[0, 0xc1, 1, 0xfe, 0x3e], 0)
            .unwrap();
        session.written(request.as_bytes().len(), 0).unwrap();
        let mut raw = vec![0x50, 0x0f];
        raw.extend(response(0x80, 0, 4, 0, 0, 0, &payload));
        session.receive(&raw, 1).unwrap();
        assert_eq!(session.response().unwrap().payload(), payload);
        assert_eq!(session.events(), 1);
    }
}

#[test]
fn transport_payload_ceiling_is_independent_of_the_negotiated_t1_ceiling() {
    for length in [258, 259, 261] {
        let mut session = pending_transfer();
        let payload: Vec<_> = (0..length).map(|index| index as u8).collect();
        let raw = response(0x80, 0, 4, 0, 0, 0, &payload);
        session.receive(&raw[..7], 1).unwrap();
        session.receive(&raw[7..], 2).unwrap();
        assert_eq!(session.response().unwrap().payload(), payload);
        assert_eq!(session.received_bytes(), 61 + 13 + length);
    }
    let mut session = pending_transfer();
    let raw = response(0x80, 0, 4, 0, 0, 0, &[0; 262]);
    assert_eq!(session.receive(&raw, 1), Err(E::Wire(W::LengthExceeded)));
    assert_eq!(session.responses(), 3);
    assert!(session.response().is_none());
    assert_eq!(
        session.begin_transfer(&TPDU, 1),
        Err(E::Wire(W::LengthExceeded))
    );
    assert_eq!(session.receive(&[], 5000), Err(E::Wire(W::LengthExceeded)));
}

const FIDI_REQUEST: [u8; 20] = [
    3, 6, 0x61, 7, 0, 0, 0, 0, 4, 1, 0, 0, 0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0, 0x22,
];
const FIDI_RESPONSE: [u8; 20] = [
    3, 6, 0x82, 7, 0, 0, 0, 0, 4, 0, 0, 1, 0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0, 0xc1,
];

fn fidi_to_set_parameters() -> S {
    let mut session = S::with_fidi();
    for command in [C::GetSlotStatus, C::PowerOn, C::GetParameters] {
        let request = session.begin_initial(0).unwrap();
        assert_eq!(request.command(), command);
        session.written(request.as_bytes().len(), 0).unwrap();
        session.receive(&initial_response(command), 0).unwrap();
    }
    assert_eq!(session.phase(), P::ReadySetParameters);
    session
}

fn pending_set_parameters() -> S {
    let mut session = fidi_to_set_parameters();
    let request = session.begin_initial(0).unwrap();
    assert_eq!(request.command(), C::SetParameters);
    assert_eq!(request.as_bytes(), FIDI_REQUEST);
    session.written(request.as_bytes().len(), 0).unwrap();
    session
}

fn initialized_fidi() -> S {
    let mut session = pending_set_parameters();
    session.receive(&FIDI_RESPONSE, 0).unwrap();
    session
}

#[test]
fn fidi_exact_set_parameters_and_shifted_ifs_vectors() {
    assert_eq!(FIDI_PARAMETERS, [0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0]);
    assert_eq!(
        response(0x82, 0, 4, 0, 0, 1, &FIDI_PARAMETERS),
        FIDI_RESPONSE
    );
    let mut session = initialized_fidi();
    assert_eq!((session.requests(), session.responses()), (4, 4));
    assert_eq!(session.received_bytes(), 81);
    assert!(session.set_parameters_accepted());
    assert_eq!(session.response(), session.set_parameters_reply_evidence());
    assert_eq!(session.response().unwrap().payload(), FIDI_PARAMETERS);
    assert_eq!(
        session.observations()[2],
        O::Parameters {
            protocol: 1,
            bytes: PARAMETERS
        }
    );
    assert_eq!(
        session.observations()[3],
        O::Parameters {
            protocol: 1,
            bytes: FIDI_PARAMETERS
        }
    );
    let evidence = session.set_parameters_reply_evidence().unwrap().clone();
    let ifs_request = [0, 0xc1, 1, 0xfe, 0x3e];
    let ifs_response = [0, 0xe1, 1, 0xfe, 0x1e];
    let request_frame = [
        3, 6, 0x6f, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0xc1, 1, 0xfe, 0x3e, 0x6a,
    ];
    let response_frame = [
        3, 6, 0x80, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0xe1, 1, 0xfe, 0x1e, 0x85,
    ];
    assert_eq!(response(0x80, 0, 5, 0, 0, 0, &ifs_response), response_frame);
    let request = session.begin_transfer(&ifs_request, 1).unwrap();
    assert_eq!(request.as_bytes(), request_frame);
    assert!(session.response().is_none());
    assert_eq!(session.set_parameters_reply_evidence(), Some(&evidence));
    session.written(request.as_bytes().len(), 1).unwrap();
    session.receive(&response_frame, 2).unwrap();
    assert_eq!(session.response().unwrap().payload(), ifs_response);
    assert_eq!(session.set_parameters_reply_evidence(), Some(&evidence));
    assert_eq!(
        (
            session.requests(),
            session.responses(),
            session.received_bytes()
        ),
        (5, 5, 99)
    );
    assert_eq!(session.begin_transfer(&TPDU, 3).unwrap().sequence(), 6);
}

#[test]
fn fidi_baseline_keeps_only_original_three_parameter_gates() {
    for index in [0, 1, 2, 3, 4, 6] {
        for value in 0..=255u8 {
            if index == 1 && value & 1 != 0 {
                continue;
            }
            let mut session = S::with_fidi();
            for command in [C::GetSlotStatus, C::PowerOn] {
                let request = session.begin_initial(0).unwrap();
                session.written(request.as_bytes().len(), 0).unwrap();
                session.receive(&initial_response(command), 0).unwrap();
            }
            let request = session.begin_initial(0).unwrap();
            session.written(request.as_bytes().len(), 0).unwrap();
            let mut params = PARAMETERS;
            params[index] = value;
            session
                .receive(&response(0x82, 0, 3, 0, 0, 1, &params), 0)
                .unwrap();
            assert_eq!(
                session.observations().last(),
                Some(&O::Parameters {
                    protocol: 1,
                    bytes: params
                })
            );
            assert!(!session.set_parameters_accepted());
            assert!(session.set_parameters_reply_evidence().is_none());
            assert_eq!(session.begin_initial(0).unwrap().as_bytes(), FIDI_REQUEST);
        }
    }
}

#[test]
fn fidi_every_changed_parameter_byte_rejects_without_sequence_five() {
    assert_eq!(
        E::SetParametersEchoRejected.name(),
        "Sec1210SetParametersEchoRejected"
    );
    for index in 0..7 {
        for value in 0..=255u8 {
            if value == FIDI_PARAMETERS[index] {
                continue;
            }
            let mut params = FIDI_PARAMETERS;
            params[index] = value;
            let mut session = pending_set_parameters();
            assert_eq!(
                session.receive(&response(0x82, 0, 4, 0, 0, 1, &params), 1),
                Err(E::SetParametersEchoRejected)
            );
            assert_eq!(
                session.set_parameters_reply_evidence().unwrap().payload(),
                params
            );
            assert_eq!(
                session.observations().last(),
                Some(&O::Parameters {
                    protocol: 1,
                    bytes: params
                })
            );
            assert!(!session.set_parameters_accepted());
            assert!(session.response().is_none());
            assert_eq!(
                session.begin_transfer(&TPDU, 2),
                Err(E::SetParametersEchoRejected)
            );
            assert_eq!(session.begin_initial(2), Err(E::SetParametersEchoRejected));
            assert_eq!(
                (session.sequence(), session.requests(), session.responses()),
                (4, 4, 3)
            );
        }
    }
}

#[test]
fn fidi_length_then_protocol_then_echo_precedence_retains_full_evidence() {
    for length in [0, 1, 6, 8, 36, 261] {
        for protocol in [0, 1] {
            let payload = vec![0xff; length];
            let mut session = pending_set_parameters();
            assert_eq!(
                session.receive(&response(0x82, 0, 4, 0, 0, protocol, &payload), 1),
                Err(E::Wire(W::PayloadRejected))
            );
            let evidence = session.set_parameters_reply_evidence().unwrap();
            assert_eq!(evidence.payload(), payload);
            assert_eq!(evidence.parameter, protocol);
            assert_eq!(session.observations().len(), 3);
            assert!(!session.set_parameters_accepted());
        }
    }
    for protocol in 0..=255u8 {
        if protocol == 1 {
            continue;
        }
        let mut session = pending_set_parameters();
        assert_eq!(
            session.receive(&response(0x82, 0, 4, 0, 0, protocol, &[0; 7]), 1),
            Err(E::ProtocolRejected)
        );
        assert_eq!(
            session.set_parameters_reply_evidence().unwrap().parameter,
            protocol
        );
        assert_eq!(
            session.observations().last(),
            Some(&O::Parameters {
                protocol,
                bytes: [0; 7]
            })
        );
        assert!(!session.set_parameters_accepted());
    }
}

#[test]
fn fidi_common_header_rejections_precede_payload_and_preserve_candidate_fields() {
    for (kind, slot, sequence, status, error, expected) in [
        (0x81, 1, 3, 0xc4, 0xff, W::SlotRejected),
        (0x81, 0, 3, 0xc4, 0xff, W::SequenceRejected),
        (0x81, 0, 4, 0x44, 0xff, W::StatusReserved),
        (0x81, 0, 4, 0xc0, 0xff, W::StatusReserved),
        (0x81, 0, 4, 0x80, 0xff, W::TimeExtensionRejected),
        (0x81, 0, 4, 0x42, 0xff, W::CommandFailed),
        (0x81, 0, 4, 0, 0xff, W::ResponseTypeRejected),
        (0x82, 0, 4, 1, 1, W::StatusErrorRejected),
        (0x82, 0, 4, 1, 0, W::IccStatusRejected),
        (0x82, 0, 4, 2, 0, W::CardAbsent),
        (0x82, 0, 4, 3, 0, W::StatusReserved),
    ] {
        let mut session = pending_set_parameters();
        assert_eq!(
            session.receive(&response(kind, slot, sequence, status, error, 0xff, &[]), 1),
            Err(E::Wire(expected))
        );
        let evidence = session.set_parameters_reply_evidence().unwrap();
        assert_eq!(
            (
                evidence.message_type,
                evidence.slot,
                evidence.sequence,
                evidence.status,
                evidence.error,
                evidence.parameter
            ),
            (kind, slot, sequence, status, error, 0xff)
        );
        assert!(evidence.payload().is_empty());
        assert!(!session.set_parameters_accepted());
        assert_eq!(session.observations().len(), 3);
        assert_eq!((session.requests(), session.responses()), (4, 3));
    }
}

#[test]
fn fidi_command_failed_keeps_raw_error_and_first_failure_for_every_later_call() {
    for error in [0, 0x0a, 0xfe, 0xff] {
        for payload in [&[][..], &PARAMETERS[..], &FIDI_PARAMETERS[..]] {
            let mut session = pending_set_parameters();
            let failed = E::Wire(W::CommandFailed);
            assert_eq!(
                session.receive(&response(0x82, 0, 4, 0x40, error, 0x80, payload), 1),
                Err(failed)
            );
            let evidence = session.set_parameters_reply_evidence().unwrap().clone();
            assert_eq!(
                (evidence.status, evidence.error, evidence.parameter),
                (0x40, error, 0x80)
            );
            assert_eq!(evidence.payload(), payload);
            assert_eq!(session.tick(u64::MAX), Err(failed));
            assert_eq!(session.begin_initial(0), Err(failed));
            assert_eq!(session.begin_transfer(&TPDU, 0), Err(failed));
            assert_eq!(session.written(20, 0), Err(failed));
            assert_eq!(session.receive(&FIDI_RESPONSE, 0), Err(failed));
            assert_eq!(session.set_parameters_reply_evidence(), Some(&evidence));
            assert_eq!(session.failure(), Some(failed));
            assert_eq!(session.phase(), P::Failed);
            assert_eq!((session.requests(), session.responses()), (4, 3));
            assert!(!session.set_parameters_accepted());
            assert!(session.response().is_none());
            assert_eq!(session.observations().len(), 3);
        }
    }
}

#[test]
fn fidi_every_fragment_split_preserves_success_and_rejected_evidence() {
    for failed in [false, true] {
        let raw = if failed {
            response(0x82, 0, 4, 0x40, 0x0a, 0, &[])
        } else {
            FIDI_RESPONSE.to_vec()
        };
        for split in 0..=raw.len() {
            let mut session = pending_set_parameters();
            let first = session.receive(&raw[..split], 1);
            let result = if split < raw.len() {
                assert_eq!(first, Ok(()));
                assert!(session.set_parameters_reply_evidence().is_none());
                assert!(!session.set_parameters_accepted());
                session.receive(&raw[split..], 2)
            } else {
                first
            };
            assert_eq!(
                result,
                if failed {
                    Err(E::Wire(W::CommandFailed))
                } else {
                    Ok(())
                }
            );
            let evidence = session.set_parameters_reply_evidence().unwrap();
            assert_eq!(evidence.error, if failed { 0x0a } else { 0 });
            assert_eq!(session.set_parameters_accepted(), !failed);
            assert_eq!(session.responses(), if failed { 3 } else { 4 });
        }
    }
    let mut session = pending_set_parameters();
    for (index, byte) in FIDI_RESPONSE.iter().enumerate() {
        session.receive(&[*byte], index as u64).unwrap();
        assert_eq!(
            session.set_parameters_reply_evidence().is_some(),
            index + 1 == FIDI_RESPONSE.len()
        );
    }
}

#[test]
fn fidi_coalesced_events_and_trailing_data_keep_acceptance_separate() {
    let mut session = pending_set_parameters();
    let mut raw = vec![0x50, 0x0f, 0x50, 1];
    raw.extend(FIDI_RESPONSE);
    session.receive(&raw, 1).unwrap();
    assert_eq!(session.events(), 2);
    assert_eq!(session.observations().len(), 6);
    assert!(session.set_parameters_accepted());
    for suffix in [vec![3], vec![0x50, 1], FIDI_RESPONSE.to_vec()] {
        let mut session = pending_set_parameters();
        let mut raw = FIDI_RESPONSE.to_vec();
        raw.extend(suffix);
        assert_eq!(session.receive(&raw, 1), Err(E::Wire(W::TrailingData)));
        assert!(session.set_parameters_reply_evidence().is_some());
        assert!(!session.set_parameters_accepted());
        assert!(session.response().is_none());
        assert_eq!(session.responses(), 3);
    }
    let mut session = pending_set_parameters();
    let mut raw = response(0x82, 0, 4, 0x40, 0x0a, 0, &[]);
    raw.extend(FIDI_RESPONSE);
    assert_eq!(session.receive(&raw, 1), Err(E::Wire(W::CommandFailed)));
    assert_eq!(session.set_parameters_reply_evidence().unwrap().error, 0x0a);
    assert!(!session.set_parameters_accepted());
}

#[test]
fn fidi_unverified_or_oversized_replies_never_manufacture_evidence() {
    let mut corrupt = response(0x81, 1, 3, 0x40, 0x0a, 0, &[]);
    *corrupt.last_mut().unwrap() ^= 1;
    for (raw, expected) in [
        (corrupt, W::ChecksumRejected),
        (response(0x82, 0, 4, 0, 0, 1, &[0; 262]), W::LengthExceeded),
        (vec![3, 0x15, 0x16], W::Nack),
        (vec![3, 0], W::PrefixRejected),
    ] {
        let mut session = pending_set_parameters();
        assert_eq!(session.receive(&raw, 1), Err(E::Wire(expected)));
        assert!(session.set_parameters_reply_evidence().is_none());
        assert!(!session.set_parameters_accepted());
        assert!(session.response().is_none());
        assert_eq!(session.observations().len(), 3);
    }
}

#[test]
fn fidi_partial_writes_and_absolute_deadlines_stop_before_acceptance() {
    let mut session = fidi_to_set_parameters();
    session.begin_initial(0).unwrap();
    assert_eq!(session.written(19, 0), Err(E::Wire(W::PartialWrite)));
    assert_eq!(session.written(20, 0), Err(E::Wire(W::PartialWrite)));
    assert_eq!(session.requests(), 3);
    assert!(session.set_parameters_reply_evidence().is_none());
    let mut session = fidi_to_set_parameters();
    session.begin_initial(0).unwrap();
    assert_eq!(session.written(20, 5000), Err(E::Wire(W::DeadlineExceeded)));
    assert_eq!(session.requests(), 4);
    for split in [0, 1, 19] {
        let mut session = pending_set_parameters();
        session.receive(&FIDI_RESPONSE[..split], 4999).unwrap();
        let expected = E::Wire(if split == 0 {
            W::DeadlineExceeded
        } else {
            W::PartialFrameDeadline
        });
        assert_eq!(
            session.receive(&FIDI_RESPONSE[split..], 5000),
            Err(expected)
        );
        assert!(session.set_parameters_reply_evidence().is_none());
        assert!(!session.set_parameters_accepted());
        assert_eq!(session.responses(), 3);
    }
    let mut session = pending_set_parameters();
    session.receive(&FIDI_RESPONSE, 4999).unwrap();
    assert!(session.set_parameters_accepted());
    let evidence = session.set_parameters_reply_evidence().unwrap().clone();
    assert_eq!(session.tick(4998), Err(E::Wire(W::ClockRegression)));
    assert_eq!(session.set_parameters_reply_evidence(), Some(&evidence));
}

#[test]
fn fidi_initialization_cannot_be_skipped_repeated_or_resumed_after_transfer() {
    for completed in 0..=3 {
        let mut session = S::with_fidi();
        for command in [C::GetSlotStatus, C::PowerOn, C::GetParameters]
            .into_iter()
            .take(completed)
        {
            let request = session.begin_initial(0).unwrap();
            session.written(request.as_bytes().len(), 0).unwrap();
            session.receive(&initial_response(command), 0).unwrap();
        }
        assert_eq!(session.begin_transfer(&TPDU, 0), Err(E::StateRejected));
        assert!(!session.set_parameters_accepted());
        assert!(session.set_parameters_reply_evidence().is_none());
    }
    let mut writing = fidi_to_set_parameters();
    writing.begin_initial(0).unwrap();
    assert_eq!(writing.begin_initial(0), Err(E::StateRejected));
    let mut receiving = pending_set_parameters();
    assert_eq!(receiving.begin_initial(0), Err(E::StateRejected));
    let mut unwritten = fidi_to_set_parameters();
    unwritten.begin_initial(0).unwrap();
    assert_eq!(
        unwritten.receive(&FIDI_RESPONSE, 0),
        Err(E::Wire(W::UnsolicitedResponse))
    );
    assert!(unwritten.set_parameters_reply_evidence().is_none());
    for stage in 0..=3 {
        let mut session = initialized_fidi();
        if stage > 0 {
            let request = session.begin_transfer(&TPDU, 0).unwrap();
            if stage > 1 {
                session.written(request.as_bytes().len(), 0).unwrap();
            }
            if stage > 2 {
                session
                    .receive(&response(0x80, 0, 5, 0, 0, 0, &TPDU), 0)
                    .unwrap();
            }
        }
        let evidence = session.set_parameters_reply_evidence().unwrap().clone();
        assert_eq!(session.begin_initial(0), Err(E::StateRejected));
        assert_eq!(session.set_parameters_reply_evidence(), Some(&evidence));
        assert!(session.set_parameters_accepted());
    }
}

#[test]
fn fidi_default_path_never_captures_or_accepts_parameter_setting() {
    let mut session = initialized();
    assert!(!session.set_parameters_accepted());
    assert!(session.set_parameters_reply_evidence().is_none());
    let request = session.begin_transfer(&TPDU, 0).unwrap();
    assert_eq!(request.sequence(), 4);
    session.written(request.as_bytes().len(), 0).unwrap();
    assert_eq!(
        session.receive(&FIDI_RESPONSE, 0),
        Err(E::Wire(W::ResponseTypeRejected))
    );
    assert!(!session.set_parameters_accepted());
    assert!(session.set_parameters_reply_evidence().is_none());
    assert_eq!(session.responses(), 3);
}

#[test]
fn fidi_command_and_receive_limits_include_set_parameters() {
    let mut session = initialized_fidi();
    for sequence in 5..=128 {
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
    assert!(session.set_parameters_accepted());
    let mut session = initialized_fidi();
    let mut received = 81;
    for sequence in 5..=128 {
        let request = session.begin_transfer(&TPDU, 0).unwrap();
        session.written(request.as_bytes().len(), 0).unwrap();
        let raw = response(0x80, 0, sequence, 0, 0, 0, &[0; 261]);
        let result = session.receive(&raw, 0);
        if received + raw.len() > 8192 {
            assert_eq!(result, Err(E::Wire(W::ReceiveLimitExceeded)));
            assert_eq!(session.received_bytes(), received);
            assert_eq!(
                session.set_parameters_reply_evidence().unwrap().payload(),
                FIDI_PARAMETERS
            );
            return;
        }
        result.unwrap();
        received += raw.len();
        assert_eq!(session.received_bytes(), received);
    }
    panic!("receive ceiling should be reached");
}

#[test]
fn fidi_events_and_hardware_errors_cannot_stand_in_for_a_reply() {
    let mut session = pending_set_parameters();
    for now in 1..=64 {
        session.receive(&[0x50, 1], now).unwrap();
    }
    assert_eq!(
        session.receive(&[0x50, 1], 65),
        Err(E::Wire(W::EventLimitExceeded))
    );
    assert!(session.set_parameters_reply_evidence().is_none());
    assert!(!session.set_parameters_accepted());
    let mut session = pending_set_parameters();
    session.receive(&[0x50, 1], 4999).unwrap();
    assert_eq!(
        session.receive(&[], 5000),
        Err(E::Wire(W::DeadlineExceeded))
    );
    for (raw, expected) in [
        (vec![0x50, 0], W::CardAbsent),
        (vec![0x50, 0x11], W::EventBitmapRejected),
        (vec![0x51, 0, 4, 0xab], W::HardwareError),
    ] {
        let mut session = pending_set_parameters();
        assert_eq!(session.receive(&raw, 1), Err(E::Wire(expected)));
        assert!(session.set_parameters_reply_evidence().is_none());
        assert!(!session.set_parameters_accepted());
        assert_eq!(session.responses(), 3);
    }
}
