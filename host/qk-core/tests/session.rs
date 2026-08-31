//! Cross-endpoint qk-io round trips and terminal hostile-peer handling.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreReceiveEvent, CoreSession, CoreState,
    Interruption, IoRejection, MockCardSlot, MockDisplay, MockKeypad, Source as CoreSource,
};
use qk_io::{
    BrokerReply, BrokerSession, BrokerState, MockInput, Source as IoSource, A1_CANDIDATE_BYTES,
    KIT_CANDIDATE_BYTES,
};
use qk_ipc::{IpcError, ReceivedFrame, StreamDecoder};

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("exact capability set")
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn deliver_fragmented(session: &mut CoreSession, bytes: &[u8]) -> CoreReceiveEvent {
    let split = bytes.len().min(13);
    let prefix = session
        .receive(&bytes[..split], false)
        .expect("fragment prefix");
    assert_eq!(prefix.consumed(), split);
    assert_eq!(prefix.event(), CoreReceiveEvent::NeedMore);
    let suffix = session
        .receive(&bytes[split..], false)
        .expect("fragment suffix");
    assert_eq!(suffix.consumed(), bytes.len() - split);
    suffix.event()
}

fn open_cross_endpoint() -> (CoreSession, BrokerSession) {
    let (mut core, opening) = CoreSession::start(CoreMode::Setup, grants()).expect("core open");
    let mut broker = BrokerSession::new();
    let opening = decode_one(opening.frame_bytes());
    let ready = broker
        .accept(&opening, None, None)
        .expect("broker ready reply");
    assert_eq!(
        deliver_fragmented(&mut core, ready.frame_bytes()),
        CoreReceiveEvent::SessionReady
    );
    assert_eq!(core.state(), CoreState::Ready);
    assert_eq!(broker.state(), BrokerState::Idle);
    (core, broker)
}

fn patterned(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add((index as u8).wrapping_mul(29)))
        .collect()
}

fn media_record(payload: &[u8]) -> Vec<u8> {
    let name = b"slice4.psbt";
    let mut record = Vec::with_capacity(1 + name.len() + 4 + payload.len());
    record.push(name.len() as u8);
    record.extend_from_slice(name);
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    record
}

fn base32(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = Vec::with_capacity((input.len() * 8).div_ceil(5));
    let mut accumulator = 0u16;
    let mut bits = 0usize;
    for byte in input {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[usize::from((accumulator >> bits) & 0x1f)]);
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 {
        output.push(ALPHABET[usize::from((accumulator << (5 - bits)) & 0x1f)]);
    }
    output
}

fn bbqr_record(payload: &[u8]) -> Vec<u8> {
    let mut frame = b"B$2P0100".to_vec();
    frame.extend_from_slice(&base32(payload));
    let mut record = Vec::with_capacity(4 + frame.len());
    record.extend_from_slice(&1u16.to_le_bytes());
    record.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    record.extend_from_slice(&frame);
    record
}

fn input_case(source: CoreSource) -> (IoSource, Vec<u8>, usize) {
    match source {
        CoreSource::CameraA1Candidate => {
            let payload = patterned(A1_CANDIDATE_BYTES, 0x11);
            (IoSource::CameraA1Candidate, payload, A1_CANDIDATE_BYTES)
        }
        CoreSource::CameraKitCandidate => {
            let payload = patterned(KIT_CANDIDATE_BYTES, 0x22);
            (IoSource::CameraKitCandidate, payload, KIT_CANDIDATE_BYTES)
        }
        CoreSource::CameraBbqrPsbt => {
            let payload = patterned(113, 0x33);
            let length = payload.len();
            (IoSource::CameraBbqrPsbt, bbqr_record(&payload), length)
        }
        CoreSource::MediaPsbt => {
            let payload = patterned(262_145, 0x44);
            let length = payload.len();
            (IoSource::MediaPsbt, media_record(&payload), length)
        }
    }
}

fn round_trip(source: CoreSource) {
    let (mut core, mut broker) = open_cross_endpoint();
    let (io_source, input_bytes, expected_len) = input_case(source);
    let mut input = MockInput::try_new(io_source, &input_bytes).expect("mock input");

    let begin = core.begin_ingress(source).expect("begin ingress");
    let begin = decode_one(begin.frame_bytes());
    let reply = broker
        .accept(&begin, Some(&mut input), None)
        .expect("begin reply");
    assert_eq!(
        deliver_fragmented(&mut core, reply.frame_bytes()),
        CoreReceiveEvent::IngressBegan {
            source,
            total_len: expected_len as u32,
        }
    );
    assert!(input.is_used());

    let mut offset = 0usize;
    while core.state() == CoreState::IngressReadReady {
        let read = core.request_next_chunk().expect("read ingress chunk");
        let read = decode_one(read.frame_bytes());
        let reply = broker.accept(&read, None, None).expect("read chunk reply");
        let event = deliver_fragmented(&mut core, reply.frame_bytes());
        let CoreReceiveEvent::IngressChunk {
            offset: actual_offset,
            chunk_len,
            final_chunk,
        } = event
        else {
            panic!("unexpected ingress event");
        };
        assert_eq!(actual_offset as usize, offset);
        offset += chunk_len as usize;
        assert_eq!(final_chunk, offset == expected_len);
    }

    assert_eq!(offset, expected_len);
    assert_eq!(core.state(), CoreState::IngressComplete);
    assert_eq!(broker.state(), BrokerState::Idle);
    let completed = core.completed_ingress().expect("sealed hostile input");
    assert_eq!(completed.source(), source);
    assert_eq!(completed.len(), expected_len);
    assert!(!completed.is_empty());
}

#[test]
fn all_four_qk_io_sources_round_trip_through_fragmented_qkip_streams() {
    for source in [
        CoreSource::CameraA1Candidate,
        CoreSource::CameraKitCandidate,
        CoreSource::CameraBbqrPsbt,
        CoreSource::MediaPsbt,
    ] {
        round_trip(source);
    }
}

#[test]
fn coalesced_frames_consume_one_then_a_stale_peer_reply_terminates() {
    let (mut core, opening) = CoreSession::start(CoreMode::A1B, grants()).expect("core open");
    let mut broker = BrokerSession::new();
    let opening = decode_one(opening.frame_bytes());
    let ready = broker
        .accept(&opening, None, None)
        .expect("broker ready reply");
    let mut coalesced = ready.frame_bytes().to_vec();
    coalesced.extend_from_slice(ready.frame_bytes());

    let first = core
        .receive(&coalesced, false)
        .expect("first coalesced frame");
    assert_eq!(first.consumed(), ready.len());
    assert_eq!(first.event(), CoreReceiveEvent::SessionReady);
    assert_eq!(core.state(), CoreState::Ready);

    assert_eq!(
        core.receive(&coalesced[first.consumed()..], false),
        Err(CoreError::Ipc(IpcError::NoOutstandingExchange))
    );
    assert_eq!(core.state(), CoreState::Terminated);
    assert_eq!(core.terminal_reason(), Some(Interruption::OperationFailed));
}

#[test]
fn every_invalid_public_transition_is_absorbing() {
    let (mut begin, _) = CoreSession::start(CoreMode::Setup, grants()).expect("begin session");
    assert_eq!(
        begin.begin_ingress(CoreSource::CameraA1Candidate).err(),
        Some(CoreError::InvalidTransition)
    );
    assert_eq!(begin.state(), CoreState::Terminated);
    assert_eq!(
        begin.begin_ingress(CoreSource::CameraA1Candidate).err(),
        Some(CoreError::CoreTerminated)
    );

    let (mut read, _) = CoreSession::start(CoreMode::Setup, grants()).expect("read session");
    assert_eq!(
        read.request_next_chunk().err(),
        Some(CoreError::InvalidTransition)
    );
    assert_eq!(read.state(), CoreState::Terminated);
    assert_eq!(
        read.request_next_chunk().err(),
        Some(CoreError::CoreTerminated)
    );

    let (mut close, _) = CoreSession::start(CoreMode::Setup, grants()).expect("close session");
    assert_eq!(
        close.begin_close().err(),
        Some(CoreError::InvalidTransition)
    );
    assert_eq!(close.state(), CoreState::Terminated);
    assert_eq!(close.begin_close().err(), Some(CoreError::CoreTerminated));
}

#[test]
fn ancillary_data_midframe_eof_and_clean_peer_loss_are_terminal_by_name() {
    let (mut ancillary, opening) =
        CoreSession::start(CoreMode::Setup, grants()).expect("ancillary session");
    assert_eq!(
        ancillary.receive(opening.frame_bytes(), true),
        Err(CoreError::Ipc(IpcError::AncillaryData))
    );
    assert_eq!(ancillary.state(), CoreState::Terminated);

    let (mut partial, opening) =
        CoreSession::start(CoreMode::Setup, grants()).expect("partial session");
    assert_eq!(
        partial
            .receive(&opening.frame_bytes()[..9], false)
            .expect("partial prefix")
            .event(),
        CoreReceiveEvent::NeedMore
    );
    assert_eq!(
        partial.connection_closed(),
        Err(CoreError::Ipc(IpcError::ConnectionClosedMidFrame))
    );
    assert_eq!(partial.state(), CoreState::Terminated);
    assert_eq!(partial.terminal_reason(), Some(Interruption::PeerLost));

    let (mut clean, _) = CoreSession::start(CoreMode::Kit, grants()).expect("clean session");
    assert_eq!(clean.connection_closed(), Ok(Interruption::PeerLost));
    assert_eq!(clean.state(), CoreState::Terminated);
    assert_eq!(clean.terminal_reason(), Some(Interruption::PeerLost));
}

#[test]
fn broker_named_rejection_is_reparsed_then_terminates_the_core_shell() {
    let (mut core, mut broker) = open_cross_endpoint();
    let bytes = patterned(KIT_CANDIDATE_BYTES, 0x66);
    let mut wrong_source =
        MockInput::try_new(IoSource::CameraKitCandidate, &bytes).expect("wrong source input");
    let begin = core
        .begin_ingress(CoreSource::CameraA1Candidate)
        .expect("begin ingress");
    let begin = decode_one(begin.frame_bytes());
    let rejection: BrokerReply = broker
        .accept(&begin, Some(&mut wrong_source), None)
        .expect("named broker rejection");

    assert_eq!(
        core.receive(rejection.frame_bytes(), false),
        Err(CoreError::IoRejected(IoRejection::SourceKindMismatch))
    );
    assert!(wrong_source.is_used());
    assert_eq!(core.state(), CoreState::Terminated);
    assert_eq!(core.terminal_reason(), Some(Interruption::OperationFailed));
}
