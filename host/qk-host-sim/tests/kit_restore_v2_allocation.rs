//! Slice-10 owns no dynamic storage; only the frozen qk-bip32 route boundary allocates.

use qk_host_sim::{
    CardRemainsStatementV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, HumanAssertionDigitV2,
    KeypadKey, KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2,
    KitRestoreActionV2, KitRestoreDispositionV2, KitRestoreSessionV2, ScreenFlowV2, ScreenKindV2,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const INHERITED_ALLOCATION_BYTES: usize = 165;

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static INHERITED: Cell<usize> = const { Cell::new(0) };
    static OTHER: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
            let _ = ALLOCATED_BYTES.try_with(|count| count.set(count.get() + layout.size()));
            if layout.size() == INHERITED_ALLOCATION_BYTES {
                let _ = INHERITED.try_with(|count| count.set(count.get() + 1));
            } else {
                let _ = OTHER.try_with(|count| count.set(count.get() + 1));
            }
        }
        // SAFETY: forwarding the unchanged layout to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarding the allocation and its original layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, [usize; 4]) {
    ALLOCATIONS.with(|value| value.set(0));
    ALLOCATED_BYTES.with(|value| value.set(0));
    INHERITED.with(|value| value.set(0));
    OTHER.with(|value| value.set(0));
    COUNTING.with(|value| value.set(true));
    let result = operation();
    COUNTING.with(|value| value.set(false));
    let counts = [
        ALLOCATIONS.with(Cell::get),
        ALLOCATED_BYTES.with(Cell::get),
        INHERITED.with(Cell::get),
        OTHER.with(Cell::get),
    ];
    (result, counts)
}

fn assert_counts(actual: [usize; 4], inherited: usize) {
    assert_eq!(
        actual,
        [
            inherited,
            inherited * INHERITED_ALLOCATION_BYTES,
            inherited,
            0,
        ]
    );
}

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered fixture field")
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("registered lowercase hex"),
    }
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn descriptors() -> [[u8; 306]; 2] {
    [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
    ]
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).unwrap(),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn ready() -> qk_host_sim::KitIntakeReadyV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    root_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(KitDoorV2::KitRestore),
        ScreenKindV2::KitDoorConfirmation,
    );
    root_continue(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(KitDoorV2::KitRestore),
        ScreenKindV2::ScanKitShareOne,
    );
    let mut intake = KitIntakeSessionV2::begin(flow, KitInputModeV2::Scanner).unwrap();
    let mut one = hex_array::<142>(field(KIT_SHARES, "frame_1_hex"));
    let mut two = hex_array::<142>(field(KIT_SHARES, "frame_2_hex"));
    assert!(matches!(
        intake.submit_scanner_frame(&mut one).unwrap(),
        KitIntakeOutcomeV2::FirstShareAccepted(_)
    ));
    let KitIntakeOutcomeV2::Ready(ready) = intake.submit_scanner_frame(&mut two).unwrap() else {
        panic!("registered pair releases readiness");
    };
    ready
}

#[test]
fn rebind_has_only_eight_inherited_route_allocations() {
    let descriptors = descriptors();
    let (session, counts) = measured(|| {
        KitRestoreSessionV2::begin(
            ready(),
            &descriptors,
            HumanAssertionDigitV2::new(4).unwrap(),
        )
    });
    assert_counts(counts, 8);
    drop(session.unwrap());
}

#[test]
fn staged_replacement_and_every_later_operation_allocate_zero() {
    let mut session = KitRestoreSessionV2::begin(
        ready(),
        &descriptors(),
        HumanAssertionDigitV2::new(4).unwrap(),
    )
    .unwrap();

    let (_, counts) = measured(|| session.select_action(KitRestoreActionV2::ReplacementB));
    assert_counts(counts, 0);
    let (_, counts) = measured(|| session.confirm_card_remains(CardRemainsStatementV2::InHand));
    assert_counts(counts, 0);

    let mut surviving_a1 = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let (prepared, counts) = measured(|| session.prepare_replacement_b(&mut surviving_a1));
    assert_counts(counts, 0);
    prepared.unwrap();
    assert_eq!(surviving_a1, [0u8; 67]);

    let (outcome, counts) = measured(|| {
        session.execute_replacement_b(KeypadKey::FourLeft, |_| KitRestoreDispositionV2::Accepted)
    });
    assert_counts(counts, 0);
    drop(outcome.unwrap());
}
