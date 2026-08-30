//! Slice-11 HOST allocation ledger for the bounded one-input golden sweep.

use qk_host_sim::{
    CoordinatorCompletenessStatementV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, KeypadKey,
    KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2, KitSpendAssertionDigitV2,
    KitSpendSessionV2, ScreenFlowV2, ScreenKindV2,
};
use qk_psbt::{InputSource, ReplacementReceiveIndexV2};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const KIT_SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const SPEND: &str = include_str!("fixtures/kit_spend_v2.txt");

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
            let _ = ALLOCATED_BYTES.try_with(|count| count.set(count.get() + layout.size()));
        }
        // SAFETY: the unchanged layout is forwarded to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the allocation and its original layout are forwarded.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, [usize; 2]) {
    ALLOCATIONS.with(|value| value.set(0));
    ALLOCATED_BYTES.with(|value| value.set(0));
    COUNTING.with(|value| value.set(true));
    let result = operation();
    COUNTING.with(|value| value.set(false));
    (
        result,
        [ALLOCATIONS.with(Cell::get), ALLOCATED_BYTES.with(Cell::get)],
    )
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

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex(value).try_into().expect("registered width")
}

fn descriptors(prefix: &str) -> [[u8; 306]; 2] {
    [
        field(SPEND, &format!("{prefix}_receive_descriptor"))
            .as_bytes()
            .try_into()
            .unwrap(),
        field(SPEND, &format!("{prefix}_change_descriptor"))
            .as_bytes()
            .try_into()
            .unwrap(),
    ]
}

fn continue_to(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).unwrap(),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn ready() -> qk_host_sim::KitIntakeReadyV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    continue_to(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    continue_to(
        &mut flow,
        FlowEventV2::SelectKitDoor(KitDoorV2::KitSpend),
        ScreenKindV2::KitDoorConfirmation,
    );
    continue_to(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(KitDoorV2::KitSpend),
        ScreenKindV2::ScanKitShareOne,
    );
    let mut intake = KitIntakeSessionV2::begin(flow, KitInputModeV2::Scanner).unwrap();
    let mut first = hex_array::<142>(field(KIT_SHARES, "frame_1_hex"));
    let mut second = hex_array::<142>(field(KIT_SHARES, "frame_2_hex"));
    assert!(matches!(
        intake.submit_scanner_frame(&mut first).unwrap(),
        KitIntakeOutcomeV2::FirstShareAccepted(_)
    ));
    let KitIntakeOutcomeV2::Ready(ready) = intake.submit_scanner_frame(&mut second).unwrap() else {
        panic!("registered pair releases readiness");
    };
    ready
}

#[test]
fn bounded_golden_sweep_has_a_fixed_host_allocation_ledger() {
    let old = descriptors("old");
    let replacement = descriptors("replacement");
    let (session, begin_counts) = measured(|| {
        KitSpendSessionV2::begin(ready(), &old, KitSpendAssertionDigitV2::new(4).unwrap())
    });
    assert_eq!(begin_counts, [10, 1_604]);
    let mut session = session.unwrap();

    let mut s0 = hex(field(SPEND, "s0_hex"));
    let (screen, validation_counts) = measured(|| {
        session.submit_sweep(
            &mut s0,
            InputSource::MicroSd,
            &replacement,
            ReplacementReceiveIndexV2::from_untrusted(0),
        )
    });
    screen.unwrap();
    assert_eq!(s0.iter().filter(|byte| **byte != 0).count(), 0);
    assert_eq!(validation_counts, [58, 6_668]);

    let (screen, statement_counts) = measured(|| {
        session.confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
    });
    screen.unwrap();
    assert_eq!(statement_counts, [0, 0]);

    let (outcome, signing_counts) = measured(|| session.execute(KeypadKey::FourLeft));
    outcome.unwrap();
    assert_eq!(signing_counts, [266, 28_416]);
}
