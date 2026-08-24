//! Direct M11 work is fixed-memory; inherited M9 allocations stay exact.

use qk_descriptor::{
    derive_change_script, derive_receive_script, match_change_derivation_claims,
    match_receive_derivation_claims, parse_descriptor_pair,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const PAIRS: &str = include_str!("fixtures/descriptor_pairs.txt");

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
static EXPECTED_SIZE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static OTHER_SIZE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);
const INHERITED_ALLOCATION_BYTES: usize = 165;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            ALLOCATED_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
            if layout.size() == INHERITED_ALLOCATION_BYTES {
                EXPECTED_SIZE_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            } else {
                OTHER_SIZE_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn field<'a>(block: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name}: ");
    block
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture field")
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    output
}

fn role_keys(block: &str) -> [Option<[u8; 33]>; 3] {
    [
        Some(hex(field(block, "role_a"))),
        Some(hex(field(block, "role_b"))),
        Some(hex(field(block, "role_c"))),
    ]
}

fn reset_counts() {
    COUNTING.store(false, Ordering::SeqCst);
    ALLOCATIONS.store(0, Ordering::SeqCst);
    ALLOCATED_BYTES.store(0, Ordering::SeqCst);
    EXPECTED_SIZE_ALLOCATIONS.store(0, Ordering::SeqCst);
    OTHER_SIZE_ALLOCATIONS.store(0, Ordering::SeqCst);
}

fn start_counting() {
    COUNTING.store(true, Ordering::SeqCst);
}

fn stop_counting() {
    COUNTING.store(false, Ordering::SeqCst);
}

fn assert_counts(expected: usize) {
    assert_eq!(ALLOCATIONS.load(Ordering::SeqCst), expected);
    assert_eq!(
        ALLOCATED_BYTES.load(Ordering::SeqCst),
        expected * INHERITED_ALLOCATION_BYTES
    );
    assert_eq!(EXPECTED_SIZE_ALLOCATIONS.load(Ordering::SeqCst), expected);
    assert_eq!(OTHER_SIZE_ALLOCATIONS.load(Ordering::SeqCst), 0);
}

#[test]
fn direct_work_is_zero_allocation_and_inherited_counts_are_exact() {
    let block = PAIRS
        .split("\n\n")
        .find(|block| block.contains("case: GOLDEN"))
        .unwrap();
    let receive = field(block, "receive").as_bytes();
    let change = field(block, "change").as_bytes();

    reset_counts();
    start_counting();
    let pair = parse_descriptor_pair(receive, change).unwrap();
    let wallet_id = pair.wallet_id();
    stop_counting();
    assert_counts(0);
    assert_ne!(wallet_id, [0; 32]);

    reset_counts();
    start_counting();
    let receive_script = derive_receive_script(&pair, 0).unwrap();
    stop_counting();
    assert_counts(6);

    reset_counts();
    start_counting();
    let change_script = derive_change_script(&pair, 0).unwrap();
    stop_counting();
    assert_counts(6);
    assert_ne!(receive_script, change_script);

    let receive_zero = block
        .split("derivation: ")
        .find(|part| part.starts_with("receive-0\n"))
        .unwrap();
    let change_zero = block
        .split("derivation: ")
        .find(|part| part.starts_with("change-0\n"))
        .unwrap();
    let receive_role_keys = role_keys(receive_zero);
    let change_role_keys = role_keys(change_zero);

    reset_counts();
    start_counting();
    let matched = match_receive_derivation_claims(&pair, 0, &receive_role_keys).unwrap();
    stop_counting();
    assert_counts(6);
    assert_eq!(matched, Some(receive_script));

    let partial_receive_role_keys = [receive_role_keys[0], None, None];
    reset_counts();
    start_counting();
    let matched = match_receive_derivation_claims(&pair, 0, &partial_receive_role_keys).unwrap();
    stop_counting();
    assert_counts(6);
    assert_eq!(matched, Some(receive_script));

    reset_counts();
    start_counting();
    let matched = match_change_derivation_claims(&pair, 0, &change_role_keys).unwrap();
    stop_counting();
    assert_counts(6);
    assert_eq!(matched, Some(change_script));

    reset_counts();
    start_counting();
    let _ = derive_receive_script(&pair, 1).unwrap();
    let _ = derive_change_script(&pair, 1).unwrap();
    stop_counting();
    assert_counts(12);
}
