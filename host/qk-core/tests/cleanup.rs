//! Source locks and executable accounting for every qk-core cleanup family.

const SESSION: &str = include_str!("../src/session.rs");
const SESSION_ID: &str = include_str!("../src/session_id.rs");
const NORMAL: &str = include_str!("../src/normal_v2.rs");
const NORMAL_ARTIFACT: &str = include_str!("../src/normal_artifact_v2.rs");
const SETUP: &str = include_str!("../src/setup_v2.rs");
const SETUP_ARTIFACT: &str = include_str!("../src/setup_artifact_v2.rs");
const WIPE: &str = include_str!("../src/wipe.rs");

#[test]
fn volatile_wipe_owns_the_complete_allocation_and_fences_each_clear() {
    assert!(WIPE.contains("let capacity = self.0.capacity();"));
    assert!(WIPE.contains("allocation(self.0.as_mut_ptr(), capacity);"));
    assert!(WIPE.contains("ptr::write_volatile(pointer.add(offset), 0)"));
    assert!(WIPE.contains("ptr::write_volatile(byte, 0)"));
    assert_eq!(WIPE.matches("compiler_fence(Ordering::SeqCst);").count(), 5);
    assert!(WIPE.contains("allocated_owner_clears_length_and_spare_capacity"));
    assert!(WIPE.contains("allocation_owner_clears_during_caught_unwind"));
    assert!(WIPE.contains("struct WipingValueVec<T>(Vec<T>);"));
    assert!(WIPE.contains("self.0.clear();"));
    assert!(WIPE.contains("value_owner_clears_live_and_spare_allocation_bytes"));
    assert!(WIPE.contains("value_owner_clears_nested_values_before_outer_allocation"));
    assert!(WIPE.contains("value_owner_clears_during_caught_unwind"));
    assert!(WIPE.contains("fixed_owner_clears_plaintext_on_caught_unwind"));
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
        "self.normal_response = None;",
        "self.decoder = None;",
        "self.ipc = None;",
        "drop(self.session_identity.take());",
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

#[test]
fn normal_cleanup_owns_all_retained_secrets_and_signature_bookkeeping() {
    let cleanup = NORMAL
        .split_once("fn cleanup_owned(&mut self) {")
        .expect("normal cleanup")
        .1
        .split_once("impl Drop for NormalSessionV2")
        .expect("normal cleanup end")
        .0;
    for clear in [
        "drop(self.s0.take());",
        "drop(self.card.take());",
        "drop(self.seed_a.take());",
        "drop(self.proof.take());",
        "self.pending_hold = None;",
        "self.approval = None;",
        "drop(self.artifacts.take());",
        "drop(self.transfer.take());",
        "self.result = None;",
    ] {
        assert!(cleanup.contains(clear), "missing normal cleanup {clear}");
    }
    assert_eq!(
        NORMAL.matches("WipingValueVec::try_with_capacity(").count(),
        2
    );
    assert!(NORMAL.contains("let mut seed = WipingArray::<32>::zeroed();"));
    assert!(!NORMAL.contains("let mut seed = [0u8; 32];"));
    assert!(NORMAL_ARTIFACT.contains("WipingArray::<MAX_FRAME_TEXT_BYTES>::zeroed()"));
    assert!(NORMAL_ARTIFACT.contains("begin_finish_filename_and_geometry_scratch_are_raii_wiped"));
    assert!(NORMAL.contains("impl Drop for NormalSessionV2"));
    assert!(SESSION.contains("normal_response_and_retained_session_identity_wipe_on_interruption"));
}

#[test]
fn setup_cleanup_covers_every_secret_owner_and_terminal_route() {
    for clear in [
        "self.clear_transcripts();",
        "self.clear_commitment();",
        "self.clear_nonce();",
        "drop(self.run.take());",
        "drop(self.a1_artifact.take());",
        "drop(page.take());",
    ] {
        assert!(SETUP.contains(clear), "missing setup cleanup {clear}");
    }
    assert!(SETUP.contains("impl Drop for SecretTranscriptV2"));
    assert!(SETUP.contains("impl Drop for SecretNonceV2"));
    assert!(SETUP.contains("impl Drop for SetupSessionV2"));
    assert!(SETUP.contains("self.core.setup_fail();"));
    assert!(SETUP.contains("self.core.terminate_setup(reason);"));
    assert!(SETUP_ARTIFACT.contains("impl Drop for A1PrintArtifactV2"));
    assert!(SETUP_ARTIFACT.contains("impl Drop for KitPrintArtifactV2"));
    assert_eq!(
        SETUP_ARTIFACT
            .matches("wipe::bytes(&mut self.bytes);")
            .count(),
        2
    );
}

#[cfg(feature = "fuzzing")]
mod executable {
    use qk_core::fuzz::{fuzz_start_session, reset_wiped_bytes, wiped_bytes};
    use qk_core::{
        CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreOutbound, CoreReceiveEvent,
        CoreSession, CoreState, Interruption, KeypadKey, MockCardSlot, MockDisplay, MockKeypad,
        SetupErrorV2, SetupOutcomeV2, SetupSessionV2, Source,
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

    fn opened_setup() -> SetupSessionV2 {
        let mut nonce = [0x5a; 12];
        reset_wiped_bytes();
        let (mut setup, opening) = SetupSessionV2::fuzz_start(NAMESPACE, 0, grants(), &mut nonce)
            .expect("deterministic setup");
        assert_eq!(nonce, [0; 12]);
        assert_eq!(wiped_bytes(), 44);
        let ready = reply(&opening, MessageKind::SessionReady, &[]);
        drop(opening);
        assert_eq!(
            setup.receive(&ready, false).expect("setup ready").outcome(),
            SetupOutcomeV2::Continue(qk_core::SetupStageV2::SetupStart)
        );
        setup
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

    #[test]
    fn state_preserving_entry_rejection_retains_bytes_without_cleanup() {
        let mut setup = opened_setup();
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("tier selection");
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("entropy selection");
        setup.apply_key(KeypadKey::SixRight).expect("manual mode");
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("manual entry");
        setup.apply_key(KeypadKey::One).expect("one face");
        reset_wiped_bytes();
        assert_eq!(
            setup
                .apply_key(KeypadKey::Seven)
                .expect("visible rejection")
                .outcome(),
            SetupOutcomeV2::StatePreserving(SetupErrorV2::InvalidFaceKey)
        );
        assert_eq!(setup.retained_counts(), [1, 0, 0, 0]);
        assert_eq!(wiped_bytes(), 0);
    }

    #[test]
    fn setup_cancellation_and_unwind_clear_all_fixed_owners() {
        let mut cancelled = opened_setup();
        reset_wiped_bytes();
        assert_eq!(
            cancelled.interrupt(Interruption::Cancelled),
            Ok(Interruption::Cancelled)
        );
        assert_eq!(wiped_bytes(), 412);
        assert!(cancelled.is_terminal());
        assert_eq!(
            cancelled.terminal_error(),
            Some(SetupErrorV2::Interrupted(Interruption::Cancelled))
        );

        let unwound = opened_setup();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _setup = unwound;
            panic!("test-only setup unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 812);
    }
}
