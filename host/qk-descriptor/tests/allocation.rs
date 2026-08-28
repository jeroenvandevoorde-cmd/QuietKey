//! Direct descriptor work is fixed-memory; inherited BIP32 allocations stay exact.

use qk_descriptor::{
    derive_change_script, derive_change_script_v2, derive_receive_script, derive_receive_script_v2,
    match_change_derivation_claims_v2, match_receive_derivation_claims_v2, parse_descriptor_pair,
    parse_descriptor_pair_v2,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const PAIRS_V2: &str = include_str!("fixtures/descriptor_pairs.txt");
const PAIRS_V1: &str = include_str!("../../qk-psbt/tests/fixtures/descriptor_pairs_v1.txt");

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

fn role_keys_v2(block: &str) -> [Option<[u8; 33]>; 2] {
    [
        Some(hex(field(block, "role_a"))),
        Some(hex(field(block, "role_b"))),
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
fn v2_counts_are_four_and_eight_while_v1_residue_stays_six_and_twelve() {
    let v2_block = PAIRS_V2
        .split("\n\n")
        .find(|block| block.contains("case: GOLDEN"))
        .unwrap();
    let v2_receive = field(v2_block, "receive").as_bytes();
    let v2_change = field(v2_block, "change").as_bytes();

    reset_counts();
    start_counting();
    let v2_pair = parse_descriptor_pair_v2(v2_receive, v2_change).unwrap();
    let v2_wallet_id = v2_pair.wallet_id();
    stop_counting();
    assert_counts(0);
    assert_ne!(v2_wallet_id, [0; 32]);

    reset_counts();
    start_counting();
    let v2_receive_script = derive_receive_script_v2(&v2_pair, 0).unwrap();
    stop_counting();
    assert_counts(4);

    reset_counts();
    start_counting();
    let v2_change_script = derive_change_script_v2(&v2_pair, 0).unwrap();
    stop_counting();
    assert_counts(4);
    assert_ne!(v2_receive_script, v2_change_script);

    let v2_receive_zero = v2_block
        .split("derivation: ")
        .find(|part| part.starts_with("receive-0\n"))
        .unwrap();
    let v2_change_zero = v2_block
        .split("derivation: ")
        .find(|part| part.starts_with("change-0\n"))
        .unwrap();
    let v2_receive_role_keys = role_keys_v2(v2_receive_zero);
    let v2_change_role_keys = role_keys_v2(v2_change_zero);

    reset_counts();
    start_counting();
    let matched = match_receive_derivation_claims_v2(&v2_pair, 0, &v2_receive_role_keys).unwrap();
    stop_counting();
    assert_counts(4);
    assert_eq!(matched, Some(v2_receive_script));

    let partial_v2_receive_role_keys = [v2_receive_role_keys[0], None];
    reset_counts();
    start_counting();
    let matched =
        match_receive_derivation_claims_v2(&v2_pair, 0, &partial_v2_receive_role_keys).unwrap();
    stop_counting();
    assert_counts(4);
    assert_eq!(matched, Some(v2_receive_script));

    reset_counts();
    start_counting();
    let matched = match_change_derivation_claims_v2(&v2_pair, 0, &v2_change_role_keys).unwrap();
    stop_counting();
    assert_counts(4);
    assert_eq!(matched, Some(v2_change_script));

    reset_counts();
    start_counting();
    let _ = derive_receive_script_v2(&v2_pair, 1).unwrap();
    let _ = derive_change_script_v2(&v2_pair, 1).unwrap();
    stop_counting();
    assert_counts(8);

    let v1_block = PAIRS_V1
        .split("\n\n")
        .find(|block| block.contains("case: GOLDEN"))
        .unwrap();
    let v1_receive = field(v1_block, "receive").as_bytes();
    let v1_change = field(v1_block, "change").as_bytes();

    reset_counts();
    start_counting();
    let v1_pair = parse_descriptor_pair(v1_receive, v1_change).unwrap();
    let v1_wallet_id = v1_pair.wallet_id();
    stop_counting();
    assert_counts(0);
    assert_ne!(v1_wallet_id, [0; 32]);

    reset_counts();
    start_counting();
    let v1_receive_script = derive_receive_script(&v1_pair, 0).unwrap();
    stop_counting();
    assert_counts(6);

    reset_counts();
    start_counting();
    let v1_change_script = derive_change_script(&v1_pair, 0).unwrap();
    stop_counting();
    assert_counts(6);
    assert_ne!(v1_receive_script, v1_change_script);

    reset_counts();
    start_counting();
    let _ = derive_receive_script(&v1_pair, 1).unwrap();
    let _ = derive_change_script(&v1_pair, 1).unwrap();
    stop_counting();
    assert_counts(12);
}
