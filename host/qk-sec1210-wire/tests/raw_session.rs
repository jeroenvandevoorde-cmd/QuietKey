use qk_sec1210_wire::{
    Error as W, RawCommand as C, RawError as E, RawObservation as O, RawPhase as P,
    RawSession as S, FIDI_PARAMETERS, RAW_APDU_BUDGET_MS, RAW_BWT_MS, RAW_COMMAND_BUDGET_MS,
    RAW_MAX_COMMANDS, RAW_MAX_EVENTS, RAW_MAX_OUTGOING_TPDU_BYTES, RAW_MAX_RECEIVED_BYTES,
    RAW_MAX_TIME_EXTENSIONS, RAW_MAX_WTX_MULTIPLIER, REGISTERED_ATR,
};

const IFS: [u8; 5] = [0, 0xc1, 1, 0xfe, 0x3e];
const IFS_ECHO: [u8; 5] = [0, 0xe1, 1, 0xfe, 0x1e];
const PARAMETERS: [u8; 7] = [0x11, 0x10, 0xff, 0x4d, 0, 0xfe, 0];
const TPDU: [u8; 5] = [0, 0, 1, 0x55, 0x54];

fn response(
    kind: u8,
    sequence: u8,
    status: u8,
    error: u8,
    parameter: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![3, 6, kind];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0, sequence, status, error, parameter]);
    bytes.extend_from_slice(payload);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

fn repair(bytes: &mut [u8]) {
    let last = bytes.len() - 1;
    bytes[last] = bytes[..last].iter().fold(0, |sum, byte| sum ^ byte);
}

fn block(pcb: u8, inf: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, pcb, inf.len() as u8];
    bytes.extend_from_slice(inf);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("test hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn initial_response(command: C) -> Vec<u8> {
    match command {
        C::GetSlotStatus => response(0x81, 1, 1, 0, 1, &[]),
        C::PowerOn => response(0x80, 2, 0, 0, 0, &REGISTERED_ATR),
        C::GetParameters => response(0x82, 3, 0, 0, 1, &PARAMETERS),
        C::SetParameters => response(0x82, 4, 0, 0, 1, &FIDI_PARAMETERS),
        C::XfrBlock => panic!("not an initialization command"),
    }
}

fn initialized() -> S {
    let mut session = S::new();
    for command in [
        C::GetSlotStatus,
        C::PowerOn,
        C::GetParameters,
        C::SetParameters,
    ] {
        let request = session.begin_initial(0).unwrap();
        assert_eq!(request.command(), command);
        session.written(request.as_bytes().len(), 0).unwrap();
        session.receive(&initial_response(command), 0).unwrap();
    }
    session
}

fn ready() -> S {
    let mut session = initialized();
    let request = session.begin_ifs_transfer(&IFS, 0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    session
        .receive(&response(0x80, 5, 0, 0, 0, &IFS_ECHO), 0)
        .unwrap();
    session.accept_ifs(0).unwrap();
    session
}

fn pending() -> S {
    let mut session = ready();
    session.begin_apdu(0).unwrap();
    let request = session.begin_transfer(&TPDU, 0, 0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    session
}

fn accept_wtx(session: &mut S, multiplier: u8, now: u64) {
    let sequence = session.sequence();
    session
        .receive(
            &response(0x80, sequence, 0, 0, 0, &block(0xc3, &[multiplier])),
            now,
        )
        .unwrap();
}

fn wtx_transfer(session: &mut S, multiplier: u8, now: u64) -> qk_sec1210_wire::RawRequest {
    let request = session
        .begin_transfer(&block(0xe3, &[multiplier]), multiplier, now)
        .unwrap();
    session.written(request.as_bytes().len(), now).unwrap();
    request
}

fn extension(session: &S, multiplier: u8) -> Vec<u8> {
    response(0x80, session.sequence(), 0x80, multiplier, 0, &[])
}

#[test]
fn exact_five_initial_requests_are_independently_pinned() {
    let expected = [
        "03066500000000000100000061",
        "03066200000000000202000067",
        "03066c0000000000030000006a",
        "0306610700000000040100001810ff4d00fe0022",
        "03066f05000000000500000000c101fe3e6a",
    ];
    let mut session = S::default();
    for (ordinal, command) in [
        C::GetSlotStatus,
        C::PowerOn,
        C::GetParameters,
        C::SetParameters,
    ]
    .into_iter()
    .enumerate()
    {
        let request = session.begin_initial(ordinal as u64).unwrap();
        assert_eq!(request.as_bytes(), hex(expected[ordinal]));
        assert_eq!(
            (request.ordinal(), request.sequence(), request.bwi()),
            (ordinal + 1, (ordinal + 1) as u8, 0)
        );
        assert_eq!(request.host_allowance_ms(), 5000);
        assert_eq!(request.deadline_ms(), ordinal as u64 + 5000);
        assert_eq!(request.apdu_deadline_ms(), None);
        session
            .written(request.as_bytes().len(), ordinal as u64)
            .unwrap();
        session
            .receive(&initial_response(command), ordinal as u64)
            .unwrap();
    }
    assert!(session.set_parameters_accepted());
    let request = session.begin_ifs_transfer(&IFS, 4).unwrap();
    assert_eq!(request.as_bytes(), hex(expected[4]));
    session.written(request.as_bytes().len(), 4).unwrap();
    session
        .receive(&hex("03068005000000000500000000e101fe1e85"), 5)
        .unwrap();
    assert_eq!(session.phase(), P::AwaitIfsAcceptance);
    assert!(!session.ifs_accepted());
    session.accept_ifs(5).unwrap();
    assert!(session.ifs_accepted());
    assert_eq!(session.phase(), P::ReadyApdu);
    assert_eq!((session.requests(), session.responses()), (5, 5));
}

#[test]
fn initialization_parameter_gates_do_not_pin_observation_bytes() {
    for index in [0, 1, 2, 3, 4, 6] {
        for byte in [0, 0x10, 0x80, 0xfe] {
            let mut session = S::new();
            for command in [C::GetSlotStatus, C::PowerOn] {
                let request = session.begin_initial(0).unwrap();
                session.written(request.as_bytes().len(), 0).unwrap();
                session.receive(&initial_response(command), 0).unwrap();
            }
            let request = session.begin_initial(0).unwrap();
            session.written(request.as_bytes().len(), 0).unwrap();
            let mut parameters = PARAMETERS;
            parameters[index] = byte;
            session
                .receive(&response(0x82, 3, 0, 0, 1, &parameters), 0)
                .unwrap();
            assert_eq!(
                session.observations().last(),
                Some(&O::Parameters {
                    protocol: 1,
                    bytes: parameters
                })
            );
        }
    }
}

#[test]
fn set_parameters_rejection_precedence_and_decoded_evidence_are_retained() {
    let cases = [
        (
            0x81,
            0x80,
            9,
            0,
            PARAMETERS.to_vec(),
            E::Wire(W::TimeExtensionRejected),
        ),
        (
            0x81,
            0x40,
            9,
            0,
            PARAMETERS.to_vec(),
            E::Wire(W::CommandFailed),
        ),
        (
            0x80,
            0,
            0,
            1,
            PARAMETERS.to_vec(),
            E::Wire(W::ResponseTypeRejected),
        ),
        (0x82, 0, 0, 1, vec![0; 6], E::Wire(W::PayloadRejected)),
        (0x82, 0, 0, 0, FIDI_PARAMETERS.to_vec(), E::ProtocolRejected),
        (
            0x82,
            0,
            0,
            1,
            PARAMETERS.to_vec(),
            E::SetParametersEchoRejected,
        ),
    ];
    for (kind, status, error, protocol, payload, expected) in cases {
        let mut session = S::new();
        for command in [C::GetSlotStatus, C::PowerOn, C::GetParameters] {
            let request = session.begin_initial(0).unwrap();
            session.written(request.as_bytes().len(), 0).unwrap();
            session.receive(&initial_response(command), 0).unwrap();
        }
        let request = session.begin_initial(0).unwrap();
        session.written(request.as_bytes().len(), 0).unwrap();
        assert_eq!(
            session.receive(&response(kind, 4, status, error, protocol, &payload), 1),
            Err(expected)
        );
        let evidence = session.set_parameters_reply_evidence().unwrap();
        assert_eq!(
            (
                evidence.status,
                evidence.error,
                evidence.parameter,
                evidence.payload()
            ),
            (status, error, protocol, payload.as_slice())
        );
        assert_eq!(session.begin_ifs_transfer(&IFS, 1), Err(expected));
        assert!(!session.set_parameters_accepted());
    }
}

#[test]
fn ifs_confirmation_cannot_be_skipped_or_forged() {
    let mut session = initialized();
    assert_eq!(session.begin_apdu(0), Err(E::StateRejected));
    let mut session = initialized();
    let request = session.begin_ifs_transfer(&IFS, 0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    session
        .receive(&response(0x80, 5, 0, 0, 0, &TPDU), 0)
        .unwrap();
    assert_eq!(session.accept_ifs(0), Err(E::IfsRejected));
    let mut session = initialized();
    assert_eq!(session.begin_ifs_transfer(&TPDU, 0), Err(E::IfsRejected));
    let mut session = ready();
    assert_eq!(session.begin_ifs_transfer(&IFS, 0), Err(E::StateRejected));
}

#[test]
fn time_extensions_are_forbidden_in_initialization_and_ifs() {
    let mut session = S::new();
    let request = session.begin_initial(0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    assert_eq!(
        session.receive(&response(0x80, 1, 0x80, 1, 0, &[]), 0),
        Err(E::Wire(W::TimeExtensionRejected))
    );
    let mut session = initialized();
    let request = session.begin_ifs_transfer(&IFS, 0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    assert_eq!(
        session.receive(&extension(&session, 1), 0),
        Err(E::Wire(W::TimeExtensionRejected))
    );
}

#[test]
fn tpdu_storage_accepts_258_and_refuses_259_without_widening_old_constants() {
    assert_eq!(qk_sec1210_wire::READBACK_MAX_OUTGOING_TPDU_BYTES, 34);
    assert_eq!(RAW_MAX_OUTGOING_TPDU_BYTES, 258);
    let mut session = ready();
    session.begin_apdu(0).unwrap();
    let tpdu = block(0, &[0xaa; 254]);
    let request = session.begin_transfer(&tpdu, 0, 0).unwrap();
    assert_eq!(request.as_bytes().len(), 271);
    assert_eq!(&request.as_bytes()[12..270], tpdu);
    assert_eq!(request.as_bytes().iter().fold(0, |sum, byte| sum ^ byte), 0);
    let mut session = ready();
    session.begin_apdu(0).unwrap();
    assert_eq!(
        session.begin_transfer(&block(0, &[0xaa; 255]), 0, 0),
        Err(E::TransferPayloadRejected)
    );
}

#[test]
fn malformed_outgoing_blocks_and_unauthorized_wtx_fail_before_claim() {
    for tpdu in [vec![], vec![0; 3], vec![0; 6], vec![0, 0, 1, 2, 0]] {
        let mut session = ready();
        session.begin_apdu(0).unwrap();
        assert_eq!(
            session.begin_transfer(&tpdu, 0, 0),
            Err(E::TransferPayloadRejected)
        );
        assert_eq!(session.requests(), 5);
    }
    let mut session = ready();
    session.begin_apdu(0).unwrap();
    assert_eq!(
        session.begin_transfer(&block(0xe3, &[1]), 1, 0),
        Err(E::WtxResponseRejected)
    );
}

#[test]
fn fragmented_response_and_coalesced_event_extension_final_are_ordered() {
    let mut session = pending();
    let mut bytes = vec![0x50, 0x0f];
    bytes.extend(extension(&session, 0));
    bytes.extend(extension(&session, 255));
    bytes.extend(response(0x80, 6, 0, 0, 0, &TPDU));
    for byte in bytes {
        session.receive(&[byte], 1).unwrap();
    }
    assert_eq!(
        (
            session.requests(),
            session.responses(),
            session.events(),
            session.time_extension_count()
        ),
        (6, 6, 1, 2)
    );
    assert_eq!(session.response().unwrap().payload(), TPDU);
    let multipliers: Vec<_> = session
        .observations()
        .iter()
        .filter_map(|item| match item {
            O::TimeExtension { multiplier, .. } => Some(*multiplier),
            _ => None,
        })
        .collect();
    assert_eq!(multipliers, [0, 255]);

    let mut session = pending();
    let mut coalesced = vec![0x50, 3];
    coalesced.extend(extension(&session, 3));
    coalesced.extend(response(0x80, 6, 0, 0, 0, &TPDU));
    session.receive(&coalesced, 10).unwrap();
    assert_eq!(session.phase(), P::ReadyTransfer);
    assert_eq!(session.time_extension_count(), 1);
}

#[test]
fn every_extension_multiplier_is_an_observation_not_an_error_code() {
    for multiplier in 0..=255 {
        let mut session = pending();
        let before = (
            session.requests(),
            session.responses(),
            session.sequence(),
            session.ordinal(),
            session.command_deadline_ms(),
            session.apdu_deadline_ms(),
        );
        session
            .receive(&extension(&session, multiplier), 20)
            .unwrap();
        assert_eq!(
            (
                session.requests(),
                session.responses(),
                session.sequence(),
                session.ordinal(),
                session.command_deadline_ms(),
                session.apdu_deadline_ms()
            ),
            before
        );
        assert_eq!(session.phase(), P::Receiving(C::XfrBlock));
        assert_eq!(session.reply_evidence().unwrap().error, multiplier);
        assert_eq!(session.response(), None);
    }
}

#[test]
fn extension_eighth_accepted_ninth_rejected_across_wtx_commands() {
    let mut session = pending();
    for index in 0..4 {
        session.receive(&extension(&session, index), 1).unwrap();
    }
    accept_wtx(&mut session, 2, 2);
    wtx_transfer(&mut session, 2, 3);
    for index in 4..8 {
        session.receive(&extension(&session, index), 4).unwrap();
    }
    assert_eq!(session.apdu_time_extension_count(), 8);
    assert_eq!(session.time_extension_count(), 8);
    assert_eq!(
        session.receive(&extension(&session, 9), 5),
        Err(E::TimeExtensionLimitExceeded)
    );
    assert_eq!(session.time_extension_count(), 8);
    assert_eq!(session.reply_evidence().unwrap().error, 9);
    assert_eq!(session.responses(), 6);
}

#[test]
fn extension_counts_reset_at_next_apdu_only_and_totals_survive() {
    let mut session = pending();
    session.receive(&extension(&session, 1), 1).unwrap();
    session
        .receive(&response(0x80, 6, 0, 0, 0, &TPDU), 2)
        .unwrap();
    session.end_apdu(3).unwrap();
    assert_eq!(session.apdu_time_extension_count(), 1);
    session.begin_apdu(4).unwrap();
    assert_eq!(session.apdu_time_extension_count(), 0);
    assert_eq!(session.time_extension_count(), 1);
    let request = session.begin_transfer(&TPDU, 0, 5).unwrap();
    session.written(request.as_bytes().len(), 5).unwrap();
    session.receive(&extension(&session, 255), 6).unwrap();
    assert_eq!(session.time_extension_count(), 2);
    assert_eq!(session.apdu_deadline_ms(), Some(30004));
}

#[test]
fn wrong_extension_shapes_follow_common_validation_precedence() {
    let cases = [
        (0x81, 0x80, 0, vec![], E::Wire(W::ResponseTypeRejected)),
        (0x80, 0x81, 0, vec![], E::Wire(W::IccStatusRejected)),
        (0x80, 0x82, 0, vec![], E::Wire(W::CardAbsent)),
        (0x80, 0x84, 0, vec![], E::Wire(W::StatusReserved)),
        (0x80, 0x80, 1, vec![], E::TimeExtensionShapeRejected),
        (0x80, 0x80, 0, vec![0], E::TimeExtensionShapeRejected),
    ];
    for (kind, status, parameter, payload, expected) in cases {
        let mut session = pending();
        assert_eq!(
            session.receive(&response(kind, 6, status, 7, parameter, &payload), 1),
            Err(expected)
        );
        assert_eq!(session.time_extension_count(), 0);
        assert_eq!(session.reply_evidence().unwrap().status, status);
    }
    for (index, value, expected) in [(7, 1, W::SlotRejected), (8, 7, W::SequenceRejected)] {
        let mut session = pending();
        let mut bytes = extension(&session, 1);
        bytes[index] = value;
        repair(&mut bytes);
        assert_eq!(session.receive(&bytes, 1), Err(E::Wire(expected)));
    }
}

#[test]
fn extensions_never_reset_deadlines_and_partial_frames_keep_their_name() {
    let mut session = pending();
    session.receive(&extension(&session, 255), 4999).unwrap();
    assert_eq!(session.tick(5000), Err(E::Wire(W::DeadlineExceeded)));
    let mut session = pending();
    session.receive(&[3, 6], 4999).unwrap();
    assert_eq!(session.tick(5000), Err(E::Wire(W::PartialFrameDeadline)));
}

#[test]
fn wtx_multipliers_1_2_and_24_set_bwi_and_host_allowance() {
    for multiplier in [1, 2, 24] {
        let mut session = pending();
        accept_wtx(&mut session, multiplier, 10);
        let request = wtx_transfer(&mut session, multiplier, 20);
        let allowance = 5000u64.max(u64::from(multiplier) * 1190);
        assert_eq!(
            (request.ordinal(), request.sequence(), request.bwi()),
            (7, 7, multiplier)
        );
        assert_eq!(request.as_bytes()[9], multiplier);
        assert_eq!(&request.as_bytes()[10..12], [0, 0]);
        assert_eq!(request.host_allowance_ms(), allowance);
        assert_eq!(request.deadline_ms(), 20 + allowance);
        assert_eq!(request.apdu_deadline_ms(), Some(30000));
        assert_eq!(&request.as_bytes()[12..17], block(0xe3, &[multiplier]));
        let receive_at = if multiplier == 24 { 6000 } else { 40 };
        session
            .receive(&response(0x80, 7, 0, 0, 0, &TPDU), receive_at)
            .unwrap();
        session.end_apdu(receive_at).unwrap();
    }
}

#[test]
fn wtx_uses_new_command_and_does_not_compound_or_reset_apdu_clock() {
    let mut session = pending();
    accept_wtx(&mut session, 24, 100);
    let first = wtx_transfer(&mut session, 24, 200);
    assert_eq!(first.deadline_ms(), 28760);
    accept_wtx(&mut session, 2, 6000);
    let second = wtx_transfer(&mut session, 2, 6001);
    assert_eq!(second.host_allowance_ms(), 5000);
    assert_eq!(second.deadline_ms(), 11001);
    assert_eq!(session.apdu_deadline_ms(), Some(30000));
    assert_eq!((session.requests(), session.responses()), (8, 7));
}

#[test]
fn absolute_apdu_deadline_clips_wtx_and_wins_over_command_or_partial_frame() {
    let mut session = pending();
    accept_wtx(&mut session, 24, 100);
    wtx_transfer(&mut session, 24, 200);
    accept_wtx(&mut session, 24, 25000);
    let request = wtx_transfer(&mut session, 24, 25001);
    assert_eq!(request.host_allowance_ms(), 28560);
    assert_eq!(request.deadline_ms(), 30000);
    session.receive(&[3], 29999).unwrap();
    assert_eq!(session.tick(30000), Err(E::ApduDeadlineExceeded));
    assert_eq!(session.failure().unwrap().name(), "T1DeadlineExceeded");
}

#[test]
fn wtx_does_not_authorize_wrong_multiplier_or_an_apdu_endpoint() {
    let mut session = pending();
    accept_wtx(&mut session, 2, 1);
    assert_eq!(session.end_apdu(2), Err(E::StateRejected));
    for multiplier in [0, 1, 25] {
        let mut session = pending();
        accept_wtx(&mut session, 2, 1);
        let expected = if multiplier == 25 {
            E::WtxMultiplierRejected
        } else {
            E::WtxResponseRejected
        };
        assert_eq!(
            session.begin_transfer(&block(0xe3, &[multiplier]), multiplier, 2),
            Err(expected)
        );
    }
    let mut session = pending();
    accept_wtx(&mut session, 2, 1);
    assert_eq!(
        session.begin_transfer(&block(0xe3, &[1]), 2, 2),
        Err(E::WtxResponseRejected)
    );
}

#[test]
fn wtx_defense_requires_the_exact_preceding_card_block() {
    for malformed in [
        block(0xe3, &[2]),
        block(0xc3, &[2, 2]),
        vec![0, 0xc3, 1, 2, 0],
        vec![1, 0xc3, 1, 2, 0xc1],
    ] {
        let mut session = pending();
        session
            .receive(&response(0x80, 6, 0, 0, 0, &malformed), 1)
            .unwrap();
        assert_eq!(
            session.begin_transfer(&block(0xe3, &[2]), 2, 2),
            Err(E::WtxResponseRejected)
        );
    }
}

#[test]
fn apdu_boundaries_cannot_reset_pending_waits_or_allow_retransmission() {
    let mut session = pending();
    assert_eq!(session.begin_apdu(1), Err(E::StateRejected));
    let mut session = pending();
    assert_eq!(session.end_apdu(1), Err(E::StateRejected));
    let mut session = ready();
    session.begin_apdu(0).unwrap();
    assert_eq!(session.end_apdu(0), Err(E::StateRejected));
    let mut session = pending();
    session
        .receive(&response(0x80, 6, 0, 0, 0, &TPDU), 1)
        .unwrap();
    assert_eq!(
        session.begin_transfer(&TPDU, 0, 2),
        Err(E::WtxResponseRejected)
    );
}

#[test]
fn command_ordinals_wrap_sequence_at_256_and_stop_before_513() {
    let mut session = ready();
    for ordinal in 6..=512 {
        session.begin_apdu(ordinal as u64).unwrap();
        let request = session.begin_transfer(&TPDU, 0, ordinal as u64).unwrap();
        assert_eq!(
            (request.ordinal(), request.sequence(), request.as_bytes()[8]),
            (ordinal, ordinal as u8, ordinal as u8)
        );
        session
            .written(request.as_bytes().len(), ordinal as u64)
            .unwrap();
        session
            .receive(
                &response(0x80, ordinal as u8, 0, 0, 0, &TPDU),
                ordinal as u64,
            )
            .unwrap();
        session.end_apdu(ordinal as u64).unwrap();
    }
    assert_eq!(
        (
            session.requests(),
            session.responses(),
            session.ordinal(),
            session.sequence()
        ),
        (512, 512, 512, 0)
    );
    session.begin_apdu(513).unwrap();
    assert_eq!(
        session.begin_transfer(&TPDU, 0, 513),
        Err(E::CommandLimitExceeded)
    );
    assert_eq!(
        session.failure().unwrap().name(),
        "Sec1210SessionCommandLimitExceeded"
    );
}

#[test]
fn sequence_wrap_still_requires_exact_pending_byte() {
    let mut session = ready();
    for ordinal in 6..256 {
        session.begin_apdu(0).unwrap();
        let request = session.begin_transfer(&TPDU, 0, 0).unwrap();
        session.written(request.as_bytes().len(), 0).unwrap();
        session
            .receive(&response(0x80, ordinal as u8, 0, 0, 0, &TPDU), 0)
            .unwrap();
        session.end_apdu(0).unwrap();
    }
    session.begin_apdu(0).unwrap();
    let request = session.begin_transfer(&TPDU, 0, 0).unwrap();
    assert_eq!(request.sequence(), 0);
    session.written(request.as_bytes().len(), 0).unwrap();
    assert_eq!(
        session.receive(&response(0x80, 255, 0, 0, 0, &TPDU), 0),
        Err(E::Wire(W::SequenceRejected))
    );
}

#[test]
fn checksum_precedes_untrusted_slot_sequence_and_status_semantics() {
    let mut session = pending();
    let mut bytes = response(0x81, 7, 0xff, 0xff, 0xff, &TPDU);
    bytes[7] = 9;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    assert_eq!(
        session.receive(&bytes, 1),
        Err(E::Wire(W::ChecksumRejected))
    );
    assert_eq!(session.reply_evidence(), None);
    assert_eq!(session.last_reply_span(), None);
}

#[test]
fn final_response_chaining_and_status_failures_are_named_and_retained() {
    for (status, error, parameter, expected) in [
        (0x40, 0x17, 0, W::CommandFailed),
        (0, 1, 0, W::StatusErrorRejected),
        (0, 0, 1, W::ChainingRejected),
        (2, 0, 0, W::CardAbsent),
    ] {
        let mut session = pending();
        assert_eq!(
            session.receive(&response(0x80, 6, status, error, parameter, &TPDU), 1),
            Err(E::Wire(expected))
        );
        assert_eq!(
            (
                session.reply_evidence().unwrap().status,
                session.reply_evidence().unwrap().error
            ),
            (status, error)
        );
        assert_eq!(session.responses(), 5);
    }
}

#[test]
fn final_response_trailing_bytes_and_unsolicited_responses_stop() {
    let mut session = pending();
    let mut bytes = response(0x80, 6, 0, 0, 0, &TPDU);
    bytes.extend([0x50, 3]);
    assert_eq!(session.receive(&bytes, 1), Err(E::Wire(W::TrailingData)));
    assert_eq!(session.responses(), 5);
    assert_eq!(session.reply_evidence().unwrap().payload(), TPDU);
    let mut session = ready();
    assert_eq!(
        session.receive(&response(0x80, 5, 0, 0, 0, &IFS_ECHO), 0),
        Err(E::Wire(W::UnsolicitedResponse))
    );
}

#[test]
fn partial_write_clock_regression_and_first_failure_are_terminal() {
    let mut session = ready();
    session.begin_apdu(10).unwrap();
    let request = session.begin_transfer(&TPDU, 0, 10).unwrap();
    assert_eq!(
        session.written(request.as_bytes().len() - 1, 11),
        Err(E::Wire(W::PartialWrite))
    );
    assert_eq!(session.tick(0), Err(E::Wire(W::PartialWrite)));
    assert_eq!(session.begin_initial(0), Err(E::Wire(W::PartialWrite)));
    assert_eq!(session.begin_apdu(0), Err(E::Wire(W::PartialWrite)));
    assert_eq!(session.requests(), 5);
    let mut session = ready();
    session.tick(10).unwrap();
    assert_eq!(session.tick(9), Err(E::Wire(W::ClockRegression)));
}

#[test]
fn deadline_boundary_before_after_and_write_work_are_included() {
    for now in [4999, 5000, 5001] {
        let mut session = pending();
        let actual = session.receive(&response(0x80, 6, 0, 0, 0, &TPDU), now);
        if now < 5000 {
            actual.unwrap();
        } else {
            assert_eq!(actual, Err(E::Wire(W::DeadlineExceeded)));
        }
    }
    let mut session = ready();
    session.begin_apdu(0).unwrap();
    let request = session.begin_transfer(&TPDU, 0, 0).unwrap();
    assert_eq!(
        session.written(request.as_bytes().len(), 5000),
        Err(E::Wire(W::DeadlineExceeded))
    );
    assert_eq!(session.requests(), 5);
}

#[test]
fn asynchronous_events_have_separate_limits_and_observations() {
    let mut session = pending();
    for _ in 0..64 {
        session.receive(&[0x50, 3], 0).unwrap();
    }
    assert_eq!(session.events(), 64);
    assert_eq!(session.time_extension_count(), 0);
    assert_eq!(
        session.receive(&[0x50, 3], 0),
        Err(E::Wire(W::EventLimitExceeded))
    );
    let mut session = pending();
    assert_eq!(session.receive(&[0x50, 2], 0), Err(E::Wire(W::CardAbsent)));
    let mut session = pending();
    assert_eq!(
        session.receive(&[0x50, 0x13], 0),
        Err(E::Wire(W::EventBitmapRejected))
    );
    let mut session = pending();
    assert_eq!(
        session.receive(&[0x51, 0, 6, 1], 0),
        Err(E::Wire(W::HardwareError))
    );
    assert!(matches!(
        session.observations().last(),
        Some(O::HardwareError { code: 1, .. })
    ));
}

#[test]
fn receive_cap_counts_all_bytes_and_stays_independent_of_old_limits() {
    let mut session = pending();
    let bytes = vec![0; RAW_MAX_RECEIVED_BYTES - session.received_bytes() + 1];
    assert_eq!(
        session.receive(&bytes, 0),
        Err(E::Wire(W::ReceiveLimitExceeded))
    );
    assert_eq!(qk_sec1210_wire::READBACK_MAX_RECEIVED_BYTES, 8192);
    assert_eq!(
        (
            RAW_MAX_COMMANDS,
            RAW_MAX_EVENTS,
            RAW_MAX_TIME_EXTENSIONS,
            RAW_MAX_WTX_MULTIPLIER
        ),
        (512, 64, 8, 24)
    );
    assert_eq!(
        (RAW_COMMAND_BUDGET_MS, RAW_APDU_BUDGET_MS, RAW_BWT_MS),
        (5000, 30000, 1190)
    );
}

#[test]
fn exact_receive_ceiling_is_accepted_and_next_byte_is_rejected() {
    let mut session = ready();
    assert_eq!(session.received_bytes(), 99);
    // These deliberately opaque replies exercise the wire bound alone; the
    // paired T=1 layer separately rejects their application-block semantics.
    for payload_len in std::iter::repeat_n(261, 119).chain(std::iter::once(50)) {
        session.begin_apdu(0).unwrap();
        let request = session.begin_transfer(&TPDU, 0, 0).unwrap();
        session.written(request.as_bytes().len(), 0).unwrap();
        session
            .receive(
                &response(0x80, session.sequence(), 0, 0, 0, &vec![0; payload_len]),
                0,
            )
            .unwrap();
        session.end_apdu(0).unwrap();
    }
    assert_eq!(session.received_bytes(), 32_768);
    session.begin_apdu(0).unwrap();
    let request = session.begin_transfer(&TPDU, 0, 0).unwrap();
    session.written(request.as_bytes().len(), 0).unwrap();
    session.receive(&[], 0).unwrap();
    assert_eq!(
        session.receive(&[3], 0),
        Err(E::Wire(W::ReceiveLimitExceeded))
    );
    assert_eq!(session.received_bytes(), 32_768);
}

#[test]
fn decoded_payload_length_may_not_expand_wire_storage_or_hide_nack() {
    let mut session = pending();
    assert_eq!(
        session.receive(&[3, 6, 0x80, 0xff, 0xff, 0xff, 0xff], 0),
        Err(E::Wire(W::LengthExceeded))
    );
    let mut session = pending();
    assert_eq!(session.receive(&[3, 0x15, 0x16], 0), Err(E::Wire(W::Nack)));
}

#[test]
fn response_spans_distinguish_coalesced_extensions_and_fragmented_final_frame() {
    let mut session = pending();
    let start = session.received_bytes();
    let mut fragment = vec![0x50, 3];
    fragment.extend(extension(&session, 1));
    fragment.extend(extension(&session, 2));
    let final_frame = response(0x80, 6, 0, 0, 0, &TPDU);
    fragment.extend(&final_frame[..3]);
    session.receive(&fragment, 1).unwrap();
    let spans: Vec<_> = session
        .observations()
        .iter()
        .filter_map(|observation| match observation {
            O::TimeExtension { span, .. } => Some(*span),
            _ => None,
        })
        .collect();
    assert_eq!(
        spans,
        [
            qk_sec1210_wire::RawFrameSpan {
                start_rx_offset: start + 2,
                end_rx_offset: start + 15
            },
            qk_sec1210_wire::RawFrameSpan {
                start_rx_offset: start + 15,
                end_rx_offset: start + 28
            },
        ]
    );
    assert_eq!(session.last_reply_span(), Some(spans[1]));
    session.receive(&[], 2).unwrap();
    session.receive(&final_frame[3..], 3).unwrap();
    assert_eq!(
        session.last_reply_span(),
        Some(qk_sec1210_wire::RawFrameSpan {
            start_rx_offset: start + 28,
            end_rx_offset: start + 28 + final_frame.len(),
        })
    );
    session.end_apdu(4).unwrap();
    session.begin_apdu(5).unwrap();
    session.begin_transfer(&TPDU, 0, 5).unwrap();
    assert_eq!(session.last_reply_span(), None);
    assert_eq!(session.reply_evidence(), None);
}

#[test]
fn semantically_rejected_reply_retains_verified_frame_span() {
    let mut session = pending();
    let start = session.received_bytes();
    let frame = response(0x80, 7, 0, 0, 0, &TPDU);
    session.receive(&frame[..8], 1).unwrap();
    assert_eq!(
        session.receive(&frame[8..], 2),
        Err(E::Wire(W::SequenceRejected))
    );
    assert_eq!(
        session.last_reply_span(),
        Some(qk_sec1210_wire::RawFrameSpan {
            start_rx_offset: start,
            end_rx_offset: start + frame.len(),
        })
    );
    assert_eq!(session.reply_evidence().unwrap().sequence, 7);
}
