#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardPresence, CoreDeviceGrants, Interruption, MockCardSlot, MockDisplay, MockKeypad,
    NormalErrorV2, NormalExportActionV2, NormalProfileV2, NormalSessionV2, NormalStageV2, Source,
};
use qk_ipc::{Direction, HEADER_BYTES, MessageKind, encode_frame, parse_frame};

const MAX_PRESENTED_BYTES: usize = 4_096;
const INTERRUPTIONS: [Interruption; 10] = [
    Interruption::Cancelled,
    Interruption::OperationFailed,
    Interruption::MediaRemoved,
    Interruption::CardRemoved,
    Interruption::SessionTimeout,
    Interruption::Shutdown,
    Interruption::Restart,
    Interruption::PowerLoss,
    Interruption::PeerLost,
    Interruption::CapabilityFailed,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EntryFact {
    profile: Option<NormalProfileV2>,
    stage: Option<NormalStageV2>,
    terminal: bool,
    error: Option<&'static str>,
    wiped: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }

    fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.offset..).unwrap_or(&[])
    }
}

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("fixed complete normal grants")
}

fn interruption_name(reason: Interruption) -> &'static str {
    let name = match reason {
        Interruption::Cancelled => "Cancelled",
        Interruption::OperationFailed => "OperationFailed",
        Interruption::MediaRemoved => "MediaRemoved",
        Interruption::CardRemoved => "CardRemoved",
        Interruption::SessionTimeout => "SessionTimeout",
        Interruption::Shutdown => "Shutdown",
        Interruption::Restart => "Restart",
        Interruption::PowerLoss => "PowerLoss",
        Interruption::PeerLost => "PeerLost",
        Interruption::CapabilityFailed => "CapabilityFailed",
    };
    assert_eq!(reason.name(), name);
    assert_eq!(reason.to_string(), name);
    name
}

fn normal_error_name(error: NormalErrorV2) -> &'static str {
    let name = match error {
        NormalErrorV2::ProfileMissing => "ProfileMissing",
        NormalErrorV2::ProfileUnknown => "ProfileUnknown",
        NormalErrorV2::ProfileMalformed => "ProfileMalformed",
        NormalErrorV2::InvalidTransition => "InvalidTransition",
        NormalErrorV2::WrongIngressSource => "WrongIngressSource",
        NormalErrorV2::CardAbsent => "CardAbsent",
        NormalErrorV2::CardBindingMismatch => "CardBindingMismatch",
        NormalErrorV2::CardDataRejected => "CardDataRejected",
        NormalErrorV2::A1Rejected => "A1Rejected",
        NormalErrorV2::RecoveredWalletMismatch => "RecoveredWalletMismatch",
        NormalErrorV2::ReviewRejected => "ReviewRejected",
        NormalErrorV2::ReviewIncomplete => "ReviewIncomplete",
        NormalErrorV2::ReviewIdentityMismatch => "ReviewIdentityMismatch",
        NormalErrorV2::ApprovalUnavailable => "ApprovalUnavailable",
        NormalErrorV2::PostApprovalYield => "PostApprovalYield",
        NormalErrorV2::RevalidationMismatch => "RevalidationMismatch",
        NormalErrorV2::SigningRejected => "SigningRejected",
        NormalErrorV2::InvalidMockSignature => "InvalidMockSignature",
        NormalErrorV2::FinalizationRejected => "FinalizationRejected",
        NormalErrorV2::ExportRouteUnavailable => "ExportRouteUnavailable",
        NormalErrorV2::ExportArtifactInvariant => "ExportArtifactInvariant",
        NormalErrorV2::ExportReceiptMismatch => "ExportReceiptMismatch",
        NormalErrorV2::BbqrVerificationMismatch => "BbqrVerificationMismatch",
        NormalErrorV2::PartialSdCompletion => "PartialSdCompletion",
        NormalErrorV2::Finished => "Finished",
        NormalErrorV2::Interrupted(reason) => interruption_name(reason),
        NormalErrorV2::Core(_) => "Core",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn response(request: &qk_core::CoreOutbound, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let request = parse_frame(request.frame_bytes()).expect("qk-core emitted canonical QKIP");
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        *request.header().session_id(),
        request.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("bounded canonical response");
    assert_eq!(written, output.len());
    output
}

fn profile_bytes(selector: u8) -> &'static [u8] {
    match selector % 6 {
        0 => &[],
        1 => &[0],
        2 => &[1, 2],
        3 => &[1],
        4 => &[2],
        5 => &[3],
        _ => unreachable!("modulo six is exhaustive"),
    }
}

fn fact(session: &mut NormalSessionV2, error: Option<NormalErrorV2>) -> EntryFact {
    let fact = EntryFact {
        profile: Some(session.profile()),
        stage: Some(session.stage()),
        terminal: session.is_terminal(),
        error: error
            .map(normal_error_name)
            .or_else(|| session.terminal_error().map(normal_error_name)),
        wiped: wiped_bytes(),
    };
    if fact.terminal {
        assert!(
            fact.wiped > 0,
            "terminating normal entry rejection must clear owned buffers"
        );
        let latched_error = session.terminal_error();
        assert_eq!(
            session
                .interrupt(Interruption::OperationFailed)
                .expect_err("a terminal session absorbs every later operation"),
            NormalErrorV2::Finished
        );
        assert_eq!(session.stage(), fact.stage.expect("started session stage"));
        assert_eq!(session.terminal_error(), latched_error);
        assert_eq!(wiped_bytes(), fact.wiped);
    }
    fact
}

fn rejection<T>(result: Result<T, NormalErrorV2>, context: &str) -> NormalErrorV2 {
    match result {
        Ok(_) => panic!("{context}"),
        Err(error) => error,
    }
}

fn drive(data: &[u8]) -> EntryFact {
    reset_wiped_bytes();
    let mut cursor = Cursor::new(data);
    let profile = profile_bytes(cursor.byte());
    let action = cursor.byte() % 13;
    let namespace = cursor.array::<12>();
    let last_counter = u32::from_le_bytes(cursor.array::<4>());
    let started = NormalSessionV2::fuzz_start(namespace, last_counter, profile, grants());
    let (mut session, opening) = match started {
        Ok(value) => value,
        Err(error) => {
            return EntryFact {
                profile: None,
                stage: None,
                terminal: true,
                error: Some(normal_error_name(error)),
                wiped: wiped_bytes(),
            };
        }
    };

    if action == 0 {
        let reason = INTERRUPTIONS[usize::from(cursor.byte()) % INTERRUPTIONS.len()];
        let error = session
            .interrupt(reason)
            .expect_err("interruption terminates");
        return fact(&mut session, Some(error));
    }
    if action == 1 {
        let error = rejection(
            session.confirm_profile(),
            "profile cannot be confirmed before ready",
        );
        return fact(&mut session, Some(error));
    }
    if action == 2 {
        let error = rejection(
            session.begin_psbt_intake(Source::MediaPsbt),
            "intake cannot begin before ready",
        );
        return fact(&mut session, Some(error));
    }

    let ready = response(&opening, MessageKind::SessionReady, &[]);
    if action == 3 {
        let error = rejection(
            session.receive(&ready, true),
            "ancillary data is always fatal",
        );
        return fact(&mut session, Some(error));
    }
    let ready_outcome = session
        .receive(&ready, false)
        .expect("canonical session ready");
    assert_eq!(ready_outcome.consumed(), ready.len());
    assert_eq!(ready_outcome.stage(), NormalStageV2::ProfileBinding);

    let error = match action {
        4 => rejection(
            session.receive(&ready, false),
            "a second ready frame is out of order",
        ),
        5 => rejection(
            session.begin_psbt_intake(Source::CameraA1Candidate),
            "profile confirmation is required",
        ),
        6 => rejection(
            session.choose_export(NormalExportActionV2::Sd {
                caller_nonce: cursor.array::<16>(),
            }),
            "export is unavailable before finalization",
        ),
        7 => rejection(
            session.complete_result(),
            "no result exists before finalization",
        ),
        8 => {
            session
                .confirm_profile()
                .expect("canonical profile confirmation");
            let reason = INTERRUPTIONS[usize::from(cursor.byte()) % INTERRUPTIONS.len()];
            session
                .interrupt(reason)
                .expect_err("interruption terminates")
        }
        9 => {
            session
                .confirm_profile()
                .expect("canonical profile confirmation");
            rejection(
                session.begin_psbt_intake(Source::CameraKitCandidate),
                "Kit input is never a normal PSBT source",
            )
        }
        10 => {
            session
                .confirm_profile()
                .expect("canonical profile confirmation");
            let source = if cursor.byte() & 1 == 0 {
                Source::CameraBbqrPsbt
            } else {
                Source::MediaPsbt
            };
            let _begin = session
                .begin_psbt_intake(source)
                .expect("valid PSBT source");
            let ancillary_present = cursor.byte() & 1 != 0;
            let presented = cursor.remaining();
            let presented = &presented[..presented.len().min(MAX_PRESENTED_BYTES)];
            match session.receive(presented, ancillary_present) {
                Err(error) => error,
                Ok(_) => session
                    .interrupt(Interruption::OperationFailed)
                    .expect_err("partial hostile input is terminated deterministically"),
            }
        }
        11 => {
            session
                .confirm_profile()
                .expect("canonical profile confirmation");
            rejection(
                session.confirm_profile(),
                "profile is immutable after confirmation",
            )
        }
        12 => {
            session
                .confirm_profile()
                .expect("canonical profile confirmation");
            let begin = session
                .begin_psbt_intake(Source::MediaPsbt)
                .expect("valid intake begin");
            let response = response(
                begin.outbound().expect("ingress request"),
                MessageKind::OperationResponse,
                &[1, 1, 0, 0, 0, 0, 0, 0],
            );
            rejection(
                session.receive(&response, false),
                "truncated inner success is named",
            )
        }
        _ => unreachable!("modulo thirteen is exhaustive"),
    };
    fact(&mut session, Some(error))
}

fn assert_drop_wipes(namespace: [u8; 12], last_counter: u32) {
    let last_counter = last_counter.min(u32::MAX - 1);
    let (session, opening) = NormalSessionV2::fuzz_start(namespace, last_counter, &[1], grants())
        .expect("fixed drop-path session");
    reset_wiped_bytes();
    drop(opening);
    drop(session);
    assert!(wiped_bytes() > 0, "drop must clear the owned session state");
}

fuzz_target!(|data: &[u8]| {
    let first = drive(data);
    let second = drive(data);
    assert_eq!(first, second);
    let mut cursor = Cursor::new(data);
    assert_drop_wipes(cursor.array(), u32::from_le_bytes(cursor.array()));
});
