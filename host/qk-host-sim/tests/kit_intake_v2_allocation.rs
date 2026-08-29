//! Every v2 slice-9 intake operation is fixed-memory on success and rejection.

use qk_host_sim::{
    FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, KeypadKey, KitDoorV2, KitInputModeV2,
    KitIntakeInterruptionV2, KitIntakeOutcomeV2, KitIntakeSessionV2, ScreenFlowV2, ScreenKindV2,
    KIT_FALLBACK_TABLE_V2,
};
use qk_kit::{encode_fallback, encode_frame, ShareIndex, FALLBACK_SYMBOLS};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let counting = COUNTING.try_with(Cell::get).unwrap_or(false);
        if counting {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|counting| counting.set(true));
    let result = operation();
    COUNTING.with(|counting| counting.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    (result, allocations)
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).unwrap(),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn flow_at_share_one(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    root_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
    root_continue(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(door),
        ScreenKindV2::ScanKitShareOne,
    );
    flow
}

fn key(number: usize) -> KeypadKey {
    match number {
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        _ => panic!("coordinate digit"),
    }
}

fn enter_fallback(session: &mut KitIntakeSessionV2, symbols: &[u8; FALLBACK_SYMBOLS]) {
    for symbol in symbols {
        let position = KIT_FALLBACK_TABLE_V2
            .iter()
            .flatten()
            .position(|candidate| candidate == symbol)
            .unwrap();
        let row = position / 8 + 1;
        let column = position % 8 + 1;
        assert!(matches!(
            session.apply_fallback_key(key(row)).unwrap(),
            KitIntakeOutcomeV2::Continue(_)
        ));
        assert!(matches!(
            session.apply_fallback_key(key(column)).unwrap(),
            KitIntakeOutcomeV2::Continue(_)
        ));
    }
}

fn frames() -> ([u8; 142], [u8; 142], [u8; 228], [u8; 228]) {
    let wallet_id = [0x31; 32];
    let frame_one = encode_frame(ShareIndex::One, &wallet_id, &[0x52; 96]);
    let frame_two = encode_frame(ShareIndex::Two, &wallet_id, &[0x73; 96]);
    let mut fallback_one = [0; FALLBACK_SYMBOLS];
    let mut fallback_two = [0; FALLBACK_SYMBOLS];
    encode_fallback(&frame_one, &mut fallback_one).unwrap();
    encode_fallback(&frame_two, &mut fallback_two).unwrap();
    (frame_one, frame_two, fallback_one, fallback_two)
}

#[test]
fn scanner_success_rejection_and_drop_allocate_zero() {
    let (mut frame_one, mut frame_two, _, _) = frames();
    let flow = flow_at_share_one(KitDoorV2::KitSpend);
    let (session, allocations) =
        measured(|| KitIntakeSessionV2::begin(flow, KitInputModeV2::Scanner));
    assert_eq!(allocations, 0);
    let mut session = session.unwrap();

    let (first, allocations) = measured(|| session.submit_scanner_frame(&mut frame_one));
    assert_eq!(allocations, 0);
    assert!(matches!(
        first.unwrap(),
        KitIntakeOutcomeV2::FirstShareAccepted(_)
    ));

    let (ready, allocations) = measured(|| session.submit_scanner_frame(&mut frame_two));
    assert_eq!(allocations, 0);
    let KitIntakeOutcomeV2::Ready(ready) = ready.unwrap() else {
        panic!("complete scanner intake");
    };
    let ((), allocations) = measured(|| drop(ready));
    assert_eq!(allocations, 0);

    let mut bad = frames().0;
    bad[141] ^= 1;
    let mut rejected = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitRestore),
        KitInputModeV2::Scanner,
    )
    .unwrap();
    let (result, allocations) = measured(|| rejected.submit_scanner_frame(&mut bad));
    assert!(result.is_err());
    assert_eq!(allocations, 0);
    let ((), allocations) = measured(|| drop(rejected));
    assert_eq!(allocations, 0);
}

#[test]
fn fallback_success_edit_rejection_and_interrupt_allocate_zero() {
    let (_, _, fallback_one, fallback_two) = frames();
    let mut session = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitRestore),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    let ((), allocations) = measured(|| enter_fallback(&mut session, &fallback_one));
    assert_eq!(allocations, 0);
    let (first, allocations) =
        measured(|| session.apply_fallback_key(KeypadKey::EqualsConfirmEnter));
    assert_eq!(allocations, 0);
    assert!(matches!(
        first.unwrap(),
        KitIntakeOutcomeV2::FirstShareAccepted(_)
    ));

    let ((), allocations) = measured(|| enter_fallback(&mut session, &fallback_two));
    assert_eq!(allocations, 0);
    let (ready, allocations) =
        measured(|| session.apply_fallback_key(KeypadKey::EqualsConfirmEnter));
    assert_eq!(allocations, 0);
    let KitIntakeOutcomeV2::Ready(ready) = ready.unwrap() else {
        panic!("complete fallback intake");
    };
    let ((), allocations) = measured(|| drop(ready));
    assert_eq!(allocations, 0);

    let mut edit = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    let (_, allocations) = measured(|| edit.apply_fallback_key(KeypadKey::One));
    assert_eq!(allocations, 0);
    let (_, allocations) = measured(|| edit.apply_fallback_key(KeypadKey::CeDelete));
    assert_eq!(allocations, 0);
    let (rejection, allocations) = measured(|| edit.apply_fallback_key(KeypadKey::Nine));
    assert!(rejection.is_err());
    assert_eq!(allocations, 0);

    let mut interrupted = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    let (result, allocations) =
        measured(|| interrupted.interrupt(KitIntakeInterruptionV2::SessionTimeout));
    assert!(result.is_err());
    assert_eq!(allocations, 0);
}
