//! Typed interruption parity with the frozen v2 screen-flow oracle.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreSession, CoreState, Interruption,
    KeypadKey as CoreKey, MockCardSlot, MockDisplay, MockKeypad,
};
use qk_host_sim::{
    FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, KeypadKey as SimKey, ScreenFlowV2, WipingReasonV2,
};

#[derive(Clone, Copy)]
enum SharedInterruption {
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

const MODES: [(CoreMode, FlowKindV2); 3] = [
    (CoreMode::Setup, FlowKindV2::Setup),
    (CoreMode::A1B, FlowKindV2::A1B),
    (CoreMode::Kit, FlowKindV2::Kit),
];

const SHARED: [SharedInterruption; 8] = [
    SharedInterruption::Cancelled,
    SharedInterruption::OperationFailed,
    SharedInterruption::MediaRemoved,
    SharedInterruption::CardRemoved,
    SharedInterruption::SessionTimeout,
    SharedInterruption::Shutdown,
    SharedInterruption::Restart,
    SharedInterruption::PowerLoss,
];

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("exact grants")
}

const fn core_reason(case: SharedInterruption) -> Interruption {
    match case {
        SharedInterruption::Cancelled => Interruption::Cancelled,
        SharedInterruption::OperationFailed => Interruption::OperationFailed,
        SharedInterruption::MediaRemoved => Interruption::MediaRemoved,
        SharedInterruption::CardRemoved => Interruption::CardRemoved,
        SharedInterruption::SessionTimeout => Interruption::SessionTimeout,
        SharedInterruption::Shutdown => Interruption::Shutdown,
        SharedInterruption::Restart => Interruption::Restart,
        SharedInterruption::PowerLoss => Interruption::PowerLoss,
    }
}

const fn sim_reason(case: SharedInterruption) -> WipingReasonV2 {
    match case {
        SharedInterruption::Cancelled => WipingReasonV2::Cancelled,
        SharedInterruption::OperationFailed => WipingReasonV2::OperationFailed,
        SharedInterruption::MediaRemoved => WipingReasonV2::MediaRemoved,
        SharedInterruption::CardRemoved => WipingReasonV2::CardRemoved,
        SharedInterruption::SessionTimeout => WipingReasonV2::SessionTimeout,
        SharedInterruption::Shutdown => WipingReasonV2::Shutdown,
        SharedInterruption::Restart => WipingReasonV2::Restart,
        SharedInterruption::PowerLoss => WipingReasonV2::PowerLoss,
    }
}

const fn sim_event(case: SharedInterruption) -> FlowEventV2<'static> {
    match case {
        SharedInterruption::Cancelled => FlowEventV2::Key(SimKey::CancelBack),
        SharedInterruption::OperationFailed => FlowEventV2::OperationFailed,
        SharedInterruption::MediaRemoved => FlowEventV2::MediaRemoved,
        SharedInterruption::CardRemoved => FlowEventV2::CardRemoved,
        SharedInterruption::SessionTimeout => FlowEventV2::SessionTimeout,
        SharedInterruption::Shutdown => FlowEventV2::Shutdown,
        SharedInterruption::Restart => FlowEventV2::Restart,
        SharedInterruption::PowerLoss => FlowEventV2::PowerLoss,
    }
}

fn apply_core(session: &mut CoreSession, case: SharedInterruption) -> Interruption {
    match case {
        SharedInterruption::Cancelled => session
            .handle_key(CoreKey::CancelBack)
            .expect("typed cancellation"),
        _ => session
            .interrupt(core_reason(case))
            .expect("typed interruption"),
    }
}

#[test]
fn three_modes_match_all_eight_frozen_v2_interruption_outcomes() {
    let mut cases = 0usize;
    for (core_mode, sim_mode) in MODES {
        for case in SHARED {
            let (mut core, open) = CoreSession::start(core_mode, grants()).expect("core session");
            assert!(!open.is_empty());
            let mut sim = ScreenFlowV2::new(sim_mode);

            let core_outcome = apply_core(&mut core, case);
            let observed_sim_reason = match sim.apply(sim_event(case)) {
                Ok(FlowApplyOutcomeV2::FailedWiped(reason)) => reason,
                Ok(_) => panic!("sim interruption did not wipe"),
                Err(_) => panic!("sim was already terminal"),
            };

            assert_eq!(core_outcome, core_reason(case));
            assert_eq!(core.state(), CoreState::Terminated);
            assert_eq!(core.terminal_reason(), Some(core_reason(case)));
            assert_eq!(observed_sim_reason, sim_reason(case));
            assert!(sim.is_finished());

            assert_eq!(
                core.interrupt(Interruption::Shutdown),
                Err(CoreError::CoreTerminated)
            );
            assert!(sim.apply(FlowEventV2::Shutdown).is_err());
            cases = cases.checked_add(1).expect("bounded case count");
        }
    }
    assert_eq!(cases, 24);
}

#[test]
fn peer_loss_is_a_core_only_absorbing_terminal_reason() {
    for (mode, _) in MODES {
        let (mut core, _open) = CoreSession::start(mode, grants()).expect("core session");
        assert_eq!(
            core.connection_closed().expect("peer-loss route"),
            Interruption::PeerLost
        );
        assert_eq!(core.state(), CoreState::Terminated);
        assert_eq!(core.terminal_reason(), Some(Interruption::PeerLost));
        assert_eq!(core.connection_closed(), Err(CoreError::CoreTerminated));
    }
}

#[test]
fn capability_failure_is_a_core_only_absorbing_terminal_reason() {
    for (mode, _) in MODES {
        let mut keypad = MockKeypad::new();
        keypad.inject_failure();
        let grants = CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(keypad),
            Some(MockCardSlot::new(CardPresence::Present)),
            false,
        )
        .expect("exact grants");
        let (mut core, _open) = CoreSession::start(mode, grants).expect("core session");

        assert_eq!(core.handle_key(CoreKey::One), Err(CoreError::KeypadFailed));
        assert_eq!(core.state(), CoreState::Terminated);
        assert_eq!(core.terminal_reason(), Some(Interruption::CapabilityFailed));
        assert_eq!(
            core.handle_key(CoreKey::One),
            Err(CoreError::CoreTerminated)
        );
    }
}
