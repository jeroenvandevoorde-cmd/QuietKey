//! Exact qk-core outbound inner-request bytes.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreMode, CoreReceiveEvent, CoreSession, MockCardSlot,
    MockDisplay, MockKeypad, Source,
};
use qk_ipc::{encode_frame, parse_frame, Direction, MessageKind, HEADER_BYTES};

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("exact capability set")
}

fn outer_response(
    session_id: [u8; 16],
    exchange_id: u32,
    kind: MessageKind,
    payload: &[u8],
) -> Vec<u8> {
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        session_id,
        exchange_id,
        payload,
        &mut output,
    )
    .expect("canonical peer response");
    assert_eq!(written, output.len());
    output
}

fn ready_session() -> (CoreSession, [u8; 16]) {
    let (mut session, opening) =
        CoreSession::start(CoreMode::Setup, grants()).expect("opening session");
    let opening = parse_frame(opening.frame_bytes()).expect("opening frame");
    let session_id = *opening.header().session_id();
    let ready = outer_response(session_id, 1, MessageKind::SessionReady, &[]);
    let outcome = session.receive(&ready, false).expect("ready response");
    assert_eq!(outcome.consumed(), ready.len());
    assert_eq!(outcome.event(), CoreReceiveEvent::SessionReady);
    (session, session_id)
}

#[test]
fn every_ingress_begin_request_is_byte_exact() {
    let cases = [
        (Source::CameraA1Candidate, 0x01),
        (Source::CameraKitCandidate, 0x02),
        (Source::CameraBbqrPsbt, 0x03),
        (Source::MediaPsbt, 0x04),
    ];

    for (source, source_byte) in cases {
        let (mut session, session_id) = ready_session();
        let outbound = session.begin_ingress(source).expect("ingress begin");
        let frame = parse_frame(outbound.frame_bytes()).expect("operation frame");
        assert_eq!(frame.header().direction(), Direction::CoreToIo);
        assert_eq!(frame.header().kind(), MessageKind::OperationRequest);
        assert_eq!(frame.header().session_id(), &session_id);
        assert_eq!(frame.header().exchange_id(), 2);
        assert_eq!(
            frame.payload(),
            &[1, 1, 0, 0, 3, 0, 0, 0, source_byte, 0, 0]
        );
    }
}

#[test]
fn ingress_read_request_carries_only_the_exact_little_endian_offset() {
    let (mut session, session_id) = ready_session();
    let begin = session
        .begin_ingress(Source::CameraA1Candidate)
        .expect("ingress begin");
    let begin = parse_frame(begin.frame_bytes()).expect("begin frame");
    assert_eq!(begin.header().exchange_id(), 2);

    let begin_body = [1, 67, 0, 0, 0];
    let mut begin_payload = vec![1, 1, 0, 0, 5, 0, 0, 0];
    begin_payload.extend_from_slice(&begin_body);
    let response = outer_response(
        session_id,
        2,
        MessageKind::OperationResponse,
        &begin_payload,
    );
    assert_eq!(
        session
            .receive(&response, false)
            .expect("begin response")
            .event(),
        CoreReceiveEvent::IngressBegan {
            source: Source::CameraA1Candidate,
            total_len: 67,
        }
    );

    let read = session.request_next_chunk().expect("read request");
    let frame = parse_frame(read.frame_bytes()).expect("read frame");
    assert_eq!(frame.header().direction(), Direction::CoreToIo);
    assert_eq!(frame.header().kind(), MessageKind::OperationRequest);
    assert_eq!(frame.header().session_id(), &session_id);
    assert_eq!(frame.header().exchange_id(), 3);
    assert_eq!(frame.payload(), &[1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
}
