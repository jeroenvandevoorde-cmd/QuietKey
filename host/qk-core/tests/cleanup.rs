//! Source locks and executable accounting for every qk-core cleanup family.

const SESSION: &str = include_str!("../src/session.rs");
const SESSION_ID: &str = include_str!("../src/session_id.rs");
const WIPE: &str = include_str!("../src/wipe.rs");

#[test]
fn volatile_wipe_owns_the_complete_allocation_and_fences_each_clear() {
    assert!(WIPE.contains("let capacity = self.0.capacity();"));
    assert!(WIPE.contains("allocation(self.0.as_mut_ptr(), capacity);"));
    assert!(WIPE.contains("ptr::write_volatile(pointer.add(offset), 0)"));
    assert!(WIPE.contains("ptr::write_volatile(byte, 0)"));
    assert_eq!(WIPE.matches("compiler_fence(Ordering::SeqCst);").count(), 3);
    assert!(WIPE.contains("allocated_owner_clears_length_and_spare_capacity"));
    assert!(WIPE.contains("allocation_owner_clears_during_caught_unwind"));
}

#[test]
fn session_identity_namespace_counter_and_returned_owner_are_all_cleared() {
    assert!(SESSION_ID.contains("wipe::bytes(&mut self.bytes);"));
    assert!(SESSION_ID.contains("wipe::bytes(&mut encoded_counter);"));
    assert!(SESSION_ID.contains("wipe::bytes(namespace);"));
    assert!(SESSION_ID.contains("wipe::bytes(&mut namespace);"));
    assert!(SESSION_ID.contains("every_owned_id_and_deterministic_namespace_clear_on_drop"));
}

#[test]
fn universal_termination_discards_every_session_owned_buffer_before_absorption() {
    let terminate = SESSION
        .split_once("fn terminate(&mut self, reason: Interruption) {")
        .expect("terminate helper")
        .1
        .split_once("fn require_live(&self)")
        .expect("terminate helper end")
        .0;
    for clear in [
        "self.expected = None;",
        "self.transfer = None;",
        "self.completed = None;",
        "self.decoder = None;",
        "self.ipc = None;",
    ] {
        assert!(terminate.contains(clear), "missing cleanup {clear}");
    }
    assert!(terminate.contains("self.state = CoreState::Terminated;"));
    assert!(terminate.contains("self.terminal_reason = Some(reason);"));

    let session_drop = SESSION
        .split_once("impl Drop for CoreSession")
        .expect("session drop")
        .1
        .split_once("fn encode_outer")
        .expect("session drop end")
        .0;
    assert!(session_drop.contains("self.terminate(Interruption::OperationFailed);"));
    assert!(SESSION.contains("Err(error) => return Err(self.fail_ipc(error))"));
    assert!(SESSION.contains("Err(error) => Err(self.fail(error))"));
}

#[cfg(feature = "fuzzing")]
mod executable {
    use qk_core::fuzz::{fuzz_start_session, reset_wiped_bytes, wiped_bytes};
    use qk_core::{
        CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreOutbound, CoreReceiveEvent,
        CoreSession, CoreState, Interruption, MockCardSlot, MockDisplay, MockKeypad, Source,
    };
    use qk_ipc::{encode_frame, parse_frame, Direction, MessageKind, HEADER_BYTES};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const NAMESPACE: [u8; 12] = [0x44; 12];
    const CANDIDATE: [u8; 67] = [0xa5; 67];

    fn grants() -> CoreDeviceGrants {
        CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Present)),
            false,
        )
        .expect("exact grants")
    }

    fn reply(request: &CoreOutbound, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
        let request = parse_frame(request.frame_bytes()).expect("request frame");
        let mut bytes = vec![0u8; HEADER_BYTES + payload.len()];
        let written = encode_frame(
            Direction::IoToCore,
            kind,
            *request.header().session_id(),
            request.header().exchange_id(),
            payload,
            &mut bytes,
        )
        .expect("response frame");
        assert_eq!(written, bytes.len());
        bytes
    }

    fn response(opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![1, opcode, 0, 0];
        payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
        payload.extend_from_slice(body);
        payload
    }

    fn opened() -> CoreSession {
        let (mut session, open) =
            fuzz_start_session(NAMESPACE, 0, CoreMode::A1B, grants()).expect("session");
        let ready = reply(&open, MessageKind::SessionReady, &[]);
        assert_eq!(
            session.receive(&ready, false).expect("ready").event(),
            CoreReceiveEvent::SessionReady
        );
        drop(open);
        session
    }

    fn active_ingress() -> CoreSession {
        let mut session = opened();
        let begin = session
            .begin_ingress(Source::CameraA1Candidate)
            .expect("begin ingress");
        let mut begin_body = vec![Source::CameraA1Candidate.wire_value()];
        begin_body.extend_from_slice(&(CANDIDATE.len() as u32).to_le_bytes());
        let begin_reply = reply(
            &begin,
            MessageKind::OperationResponse,
            &response(1, &begin_body),
        );
        assert!(matches!(
            session
                .receive(&begin_reply, false)
                .expect("begin reply")
                .event(),
            CoreReceiveEvent::IngressBegan {
                source: Source::CameraA1Candidate,
                total_len: 67
            }
        ));
        drop(begin);
        session
    }

    fn completed_ingress() -> CoreSession {
        let mut session = active_ingress();
        let read = session.request_next_chunk().expect("read request");
        let mut body = Vec::with_capacity(9 + CANDIDATE.len());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(CANDIDATE.len() as u32).to_le_bytes());
        body.push(1);
        body.extend_from_slice(&CANDIDATE);
        let read_reply = reply(&read, MessageKind::OperationResponse, &response(2, &body));
        assert!(matches!(
            session
                .receive(&read_reply, false)
                .expect("read reply")
                .event(),
            CoreReceiveEvent::IngressChunk {
                offset: 0,
                chunk_len: 67,
                final_chunk: true
            }
        ));
        assert_eq!(
            session.completed_ingress().map(|value| value.len()),
            Some(67)
        );
        drop(read);
        session
    }

    #[test]
    fn deterministic_mint_and_outbound_owner_have_exact_cleanup_counts() {
        reset_wiped_bytes();
        let (session, open) =
            fuzz_start_session(NAMESPACE, 0, CoreMode::Setup, grants()).expect("session");
        assert_eq!(wiped_bytes(), 32);

        let frame_capacity = open.len();
        reset_wiped_bytes();
        drop(open);
        assert_eq!(wiped_bytes(), frame_capacity);
        drop(session);
    }

    #[test]
    fn interruption_and_named_rejection_clear_the_active_transfer_exactly() {
        let mut interrupted = active_ingress();
        reset_wiped_bytes();
        assert_eq!(
            interrupted
                .interrupt(Interruption::SessionTimeout)
                .expect("interruption"),
            Interruption::SessionTimeout
        );
        assert_eq!(wiped_bytes(), CANDIDATE.len());
        assert_eq!(interrupted.state(), CoreState::Terminated);

        let mut rejected = active_ingress();
        let read = rejected.request_next_chunk().expect("read request");
        let malformed = reply(&read, MessageKind::OperationResponse, &response(2, &[]));
        drop(read);
        reset_wiped_bytes();
        assert_eq!(
            rejected.receive(&malformed, false),
            Err(CoreError::ResponseBodyTruncated)
        );
        assert_eq!(wiped_bytes(), CANDIDATE.len());
        assert_eq!(rejected.state(), CoreState::Terminated);
    }

    #[test]
    fn successful_close_clears_the_completed_hostile_owner_exactly() {
        let mut session = completed_ingress();
        let close = session.begin_close().expect("close request");
        let closed = reply(&close, MessageKind::SessionClosed, &[]);
        drop(close);
        reset_wiped_bytes();
        assert_eq!(
            session.receive(&closed, false).expect("closed").event(),
            CoreReceiveEvent::SessionClosed
        );
        assert_eq!(wiped_bytes(), CANDIDATE.len());
        assert_eq!(session.state(), CoreState::Closed);
    }

    #[test]
    fn drop_and_caught_unwind_clear_completed_hostile_capacity() {
        let dropped = completed_ingress();
        reset_wiped_bytes();
        drop(dropped);
        assert_eq!(wiped_bytes(), CANDIDATE.len());

        let unwound = completed_ingress();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _session = unwound;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), CANDIDATE.len());
    }
}
