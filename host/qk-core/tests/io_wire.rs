//! Exact qk-core outbound inner-request bytes.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreMode, CoreReceiveEvent, CoreSession, MockCardSlot,
    MockDisplay, MockKeypad, Source,
};
use qk_ipc::{encode_frame, parse_frame, Direction, MessageKind, HEADER_BYTES};

const IO_WIRE: &str = include_str!("../src/io_wire.rs");

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

#[test]
fn print_egress_is_exposed_only_through_two_purpose_bound_grammars() {
    for required in [
        "pub(crate) fn encode_a1_print_begin() -> [u8; 16]",
        "pub(crate) fn encode_kit_print_begin() -> [u8; 16]",
        "pub(crate) fn encode_a1_print_write(",
        "pub(crate) fn encode_kit_print_write(",
        "pub(crate) const fn encode_a1_print_finish() -> [u8; 8]",
        "pub(crate) const fn encode_kit_print_finish() -> [u8; 8]",
        "const A1_PRINT_ARTIFACT: u8 = 0x04;",
        "const KIT_PRINT_ARTIFACT: u8 = 0x05;",
        "pub(crate) const A1_PRINT_BYTES: usize = 67;",
        "pub(crate) const KIT_PRINT_BYTES: usize = 829;",
    ] {
        assert!(
            IO_WIRE.contains(required),
            "missing purpose-bound lock {required}"
        );
    }
    for forbidden in [
        "pub fn encode_egress_begin",
        "pub(crate) fn encode_egress_begin",
        "pub fn encode_egress_write",
        "pub(crate) fn encode_egress_write",
        "pub fn encode_egress_finish",
        "pub(crate) fn encode_egress_finish",
        "pub enum Sink",
        "pub enum Artifact",
    ] {
        assert!(
            !IO_WIRE.contains(forbidden),
            "generic transport surface {forbidden}"
        );
    }
}

#[test]
fn print_egress_geometry_and_success_parsers_are_source_locked() {
    for required in [
        "Self::EgressBegin => 0x03,",
        "Self::EgressWrite => 0x04,",
        "Self::EgressFinish => 0x05,",
        "const PRINT_SINK: u8 = 0x03;",
        "const EGRESS_BEGIN_BODY_BYTES: usize = 8;",
        "const EGRESS_WRITE_PREFIX_BYTES: usize = 8;",
        "const EGRESS_WRITE_RESPONSE_BYTES: usize = 4;",
        "const EGRESS_FINISH_RESPONSE_BYTES: usize = 6;",
        "ExpectedPrintResponse::Begin { artifact } => parse_egress_begin_success(body, artifact)",
        "ExpectedPrintResponse::Write { artifact } => parse_egress_write_success(body, artifact)",
        "ExpectedPrintResponse::Finish { artifact } => parse_egress_finish_success(body, artifact)",
        "if accepted_total != artifact.total_len()",
        "if byte_at(body, 0)? != PRINT_SINK || byte_at(body, 1)? != artifact.wire_value()",
        "if total_len != artifact.total_len()",
    ] {
        assert!(
            IO_WIRE.contains(required),
            "missing exact egress lock {required}"
        );
    }
}

#[test]
fn normal_export_egress_is_exposed_only_through_exact_purpose_bound_grammars() {
    for required in [
        "pub(crate) fn encode_normal_egress_write(",
        "const SD_SINK: u8 = 0x01;",
        "const BBQR_SINK: u8 = 0x02;",
        "const FINALIZED_PSBT_ARTIFACT: u8 = 0x01;",
        "const RAW_TRANSACTION_ARTIFACT: u8 = 0x02;",
        "const NORMAL_BBQR_FRAME_MAX_COUNT: u16 = 256;",
        "validate_normal_bbqr_frames(encoded_frames, frame_count)?;",
    ] {
        assert!(
            IO_WIRE.contains(required),
            "missing normal export wire lock {required}"
        );
    }
}
