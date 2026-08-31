//! Process-session identity mint invariants at the public QKIP boundary.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreMode, CoreSession, MockCardSlot, MockDisplay, MockKeypad,
};
use qk_ipc::{parse_frame, Direction, MessageKind};

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("exact capability set")
}

fn opening_identity(mode: CoreMode) -> ([u8; 16], CoreSession) {
    let (session, opening) = CoreSession::start(mode, grants()).expect("session identity mint");
    let frame = parse_frame(opening.frame_bytes()).expect("canonical opening frame");
    assert_eq!(frame.header().direction(), Direction::CoreToIo);
    assert_eq!(frame.header().kind(), MessageKind::SessionOpen);
    assert_eq!(frame.header().exchange_id(), 1);
    assert!(frame.payload().is_empty());
    (*frame.header().session_id(), session)
}

#[test]
fn one_process_namespace_and_little_endian_counter_never_reuse_an_identity() {
    let (first, first_session) = opening_identity(CoreMode::Setup);
    let (second, second_session) = opening_identity(CoreMode::A1B);
    let (third, third_session) = opening_identity(CoreMode::Kit);

    assert_eq!(&first[..12], &second[..12]);
    assert_eq!(&second[..12], &third[..12]);

    let first_counter = u32::from_le_bytes(first[12..].try_into().expect("counter bytes"));
    let second_counter = u32::from_le_bytes(second[12..].try_into().expect("counter bytes"));
    let third_counter = u32::from_le_bytes(third[12..].try_into().expect("counter bytes"));
    assert_eq!(
        second_counter,
        first_counter.checked_add(1).expect("counter space")
    );
    assert_eq!(
        third_counter,
        second_counter.checked_add(1).expect("counter space")
    );
    assert_ne!(first, second);
    assert_ne!(second, third);
    assert_ne!(first, third);

    // Keep all three owners live while the non-reuse relationship is checked.
    drop((first_session, second_session, third_session));
}
