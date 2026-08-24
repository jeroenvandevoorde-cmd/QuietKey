//! M12's closed public descriptor-ownership inventory.
//!
//! Every case builds a structurally valid PSBT v0 in memory with a full
//! `non_witness_utxo`. The M12 fixture supplies only public descriptors,
//! public derivation facts, and the closed case inventory.

use qk_descriptor::{
    derive_change_script, derive_receive_script, parse_descriptor_pair, DerivedScript,
    DescriptorPair,
};
use qk_psbt::{
    analyze_and_verify_signatures, analyze_descriptor_ownership, canonical_serialize, parse,
    DescriptorOwnershipAnalysis, InputSource, OutputOwnership, SemanticCategory,
    VerifiedAggregateStatus, VerifiedInputStatus,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const FIXTURE: &str = include_str!("fixtures/descriptor_ownership.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");
const FP: [[u8; 4]; 3] = [
    [0x11, 0x22, 0x33, 0x44],
    [0x55, 0x66, 0x77, 0x88],
    [0x99, 0xaa, 0xbb, 0xcc],
];
const FOREIGN_FP: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const HARDENED: u32 = 0x8000_0000;
const BIP48_PREFIX: [u32; 4] = [HARDENED | 48, HARDENED, HARDENED, HARDENED | 2];

struct AllocationLedger;

static LEDGER_ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS_165: AtomicUsize = AtomicUsize::new(0);
static BYTES_165: AtomicUsize = AtomicUsize::new(0);
static LIVE_165: AtomicUsize = AtomicUsize::new(0);
static MAX_LIVE_165: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for AllocationLedger {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if LEDGER_ENABLED.load(Ordering::Relaxed) && layout.size() == 165 {
            ALLOCATIONS_165.fetch_add(1, Ordering::Relaxed);
            BYTES_165.fetch_add(165, Ordering::Relaxed);
            let live = LIVE_165.fetch_add(1, Ordering::Relaxed) + 1;
            MAX_LIVE_165.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if LEDGER_ENABLED.load(Ordering::Relaxed) && layout.size() == 165 {
            LIVE_165.fetch_sub(1, Ordering::Relaxed);
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: AllocationLedger = AllocationLedger;

#[derive(Clone)]
struct RawFixtureRecord {
    key: Vec<u8>,
    value: Vec<u8>,
}

struct InputSpec {
    prevout_script: Vec<u8>,
    witness_utxo: bool,
    witness_script: Option<Vec<u8>>,
    claims: Vec<RawFixtureRecord>,
    extra_records: Vec<RawFixtureRecord>,
    mismatch_outpoint_txid: bool,
}

struct OutputSpec {
    script_pubkey: Vec<u8>,
    claims: Vec<RawFixtureRecord>,
    extra_records: Vec<RawFixtureRecord>,
}

struct ScriptOracle {
    witness_script: Vec<u8>,
    script_pubkey: Vec<u8>,
}

fn fixture_field(prefix: &str) -> &'static str {
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap()
}

fn descriptor_pair() -> DescriptorPair {
    parse_descriptor_pair(
        fixture_field("receive: ").as_bytes(),
        fixture_field("change: ").as_bytes(),
    )
    .unwrap()
}

fn descriptor_pair_named(name: &str) -> DescriptorPair {
    let block = DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == format!("case: {name}")))
        .unwrap();
    let receive = block
        .lines()
        .find_map(|line| line.strip_prefix("receive: "))
        .unwrap();
    let change = block
        .lines()
        .find_map(|line| line.strip_prefix("change: "))
        .unwrap();
    parse_descriptor_pair(receive.as_bytes(), change.as_bytes()).unwrap()
}

fn fixture_case(name: &str, class: &str, expected: &str) {
    let block = FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == format!("case: {name}")))
        .unwrap();
    assert!(
        block.lines().any(|line| line == format!("class: {class}")),
        "{name}"
    );
    assert!(
        block
            .lines()
            .any(|line| line == format!("expected: {expected}")),
        "{name}"
    );
}

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn route_keys(branch: u32, index: u32) -> [[u8; 33]; 3] {
    let route = match (branch, index) {
        (0, 0) => "route: receive-0",
        (1, 0) => "route: change-0",
        (0, 65_535) => "route: receive-65535",
        (1, 65_535) => "route: change-65535",
        _ => panic!("the static fixture has no requested route"),
    };
    let block = FIXTURE.split_once(route).unwrap().1;
    let mut keys = [[0u8; 33]; 3];
    for (role, prefix) in ["role_a: ", "role_b: ", "role_c: "].iter().enumerate() {
        let value = block
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap();
        keys[role] = decode_hex(value);
    }
    keys
}

fn script_oracle(branch: u32, index: u32) -> ScriptOracle {
    let route = match (branch, index) {
        (0, 0) => "route: receive-0",
        (1, 0) => "route: change-0",
        (0, 65_535) => "route: receive-65535",
        (1, 65_535) => "route: change-65535",
        _ => panic!("the static fixture has no requested route"),
    };
    let block = FIXTURE.split_once(route).unwrap().1;
    let witness_script = block
        .lines()
        .find_map(|line| line.strip_prefix("witness_script: "))
        .map(|value| decode_hex::<105>(value).to_vec())
        .unwrap();
    let script_pubkey = block
        .lines()
        .find_map(|line| line.strip_prefix("script_pubkey: "))
        .map(|value| decode_hex::<34>(value).to_vec())
        .unwrap();
    ScriptOracle {
        witness_script,
        script_pubkey,
    }
}

fn authority_key(role: usize) -> [u8; 33] {
    let value = fixture_field("authority_points: ")
        .split(',')
        .nth(role)
        .unwrap();
    decode_hex(value)
}

fn derived(descriptor: &DescriptorPair, branch: u32, index: u32) -> DerivedScript {
    match branch {
        0 => derive_receive_script(descriptor, index).unwrap(),
        1 => derive_change_script(descriptor, index).unwrap(),
        _ => panic!("fixture builder only derives receive/change routes"),
    }
}

fn reserve_vec(capacity: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).unwrap();
    bytes
}

fn append(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.try_reserve(value.len()).unwrap();
    bytes.extend_from_slice(value);
}

fn compact_size(bytes: &mut Vec<u8>, value: usize) {
    match value {
        0..=252 => bytes.push(value as u8),
        253..=65_535 => {
            bytes.push(0xfd);
            append(bytes, &(value as u16).to_le_bytes());
        }
        _ => panic!("fixture CompactSize exceeds u16"),
    }
}

fn raw_record(key_type: u8, key_data: &[u8], value: &[u8]) -> RawFixtureRecord {
    let mut key = reserve_vec(1 + key_data.len());
    key.push(key_type);
    append(&mut key, key_data);
    let mut copied_value = reserve_vec(value.len());
    append(&mut copied_value, value);
    RawFixtureRecord {
        key,
        value: copied_value,
    }
}

fn append_record(bytes: &mut Vec<u8>, record: &RawFixtureRecord) {
    compact_size(bytes, record.key.len());
    append(bytes, &record.key);
    compact_size(bytes, record.value.len());
    append(bytes, &record.value);
}

fn derivation_value(fingerprint: [u8; 4], path: &[u32]) -> Vec<u8> {
    let mut value = reserve_vec(4 + path.len() * 4);
    append(&mut value, &fingerprint);
    for component in path {
        append(&mut value, &component.to_le_bytes());
    }
    value
}

fn exact_path(branch: u32, index: u32) -> [u32; 6] {
    [
        BIP48_PREFIX[0],
        BIP48_PREFIX[1],
        BIP48_PREFIX[2],
        BIP48_PREFIX[3],
        branch,
        index,
    ]
}

fn claim_record(
    key_type: u8,
    public_key: &[u8],
    fingerprint: [u8; 4],
    path: &[u32],
) -> RawFixtureRecord {
    raw_record(key_type, public_key, &derivation_value(fingerprint, path))
}

fn local_claims(key_type: u8, branch: u32, index: u32) -> Vec<RawFixtureRecord> {
    let keys = route_keys(branch, index);
    let path = exact_path(branch, index);
    let mut claims = Vec::new();
    claims.try_reserve_exact(3).unwrap();
    for role in 0..3 {
        claims.push(claim_record(key_type, &keys[role], FP[role], &path));
    }
    claims
}

fn foreign_claim(key_type: u8) -> RawFixtureRecord {
    claim_record(key_type, &authority_key(0), FOREIGN_FP, &exact_path(0, 0))
}

fn set_claim_fingerprint(record: &mut RawFixtureRecord, fingerprint: [u8; 4]) {
    record.value[0..4].copy_from_slice(&fingerprint);
}

fn set_claim_path(record: &mut RawFixtureRecord, fingerprint: [u8; 4], path: &[u32]) {
    record.value = derivation_value(fingerprint, path);
}

fn set_claim_key(record: &mut RawFixtureRecord, public_key: &[u8]) {
    let key_type = record.key[0];
    record.key = raw_record(key_type, public_key, &[]).key;
}

fn owned_input(
    _descriptor: &DescriptorPair,
    branch: u32,
    index: u32,
    witness_script_present: bool,
) -> InputSpec {
    let script = script_oracle(branch, index);
    InputSpec {
        prevout_script: script.script_pubkey,
        witness_utxo: true,
        witness_script: witness_script_present.then_some(script.witness_script),
        claims: local_claims(0x06, branch, index),
        extra_records: Vec::new(),
        mismatch_outpoint_txid: false,
    }
}

fn descriptor_output(
    _descriptor: &DescriptorPair,
    branch: u32,
    index: u32,
    local_roles: usize,
) -> OutputSpec {
    let mut claims = local_claims(0x02, branch, index);
    claims.truncate(local_roles);
    OutputSpec {
        script_pubkey: script_oracle(branch, index).script_pubkey,
        claims,
        extra_records: Vec::new(),
    }
}

fn previous_transaction(script_pubkey: &[u8], salt: u8) -> Vec<u8> {
    let mut transaction = reserve_vec(96);
    append(&mut transaction, &1u32.to_le_bytes());
    transaction.push(1);
    append(&mut transaction, &[salt; 32]);
    append(&mut transaction, &0u32.to_le_bytes());
    transaction.push(0);
    append(&mut transaction, &u32::MAX.to_le_bytes());
    transaction.push(1);
    append(&mut transaction, &10_000u64.to_le_bytes());
    compact_size(&mut transaction, script_pubkey.len());
    append(&mut transaction, script_pubkey);
    append(&mut transaction, &0u32.to_le_bytes());
    transaction
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut padded = reserve_vec(bytes.len() + 72);
    append(&mut padded, bytes);
    let bit_len = (bytes.len() as u64) * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    append(&mut padded, &bit_len.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for index in 0..16 {
            words[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    sha256(&sha256(bytes))
}

fn build_psbt(inputs: &[InputSpec], outputs: &[OutputSpec]) -> Vec<u8> {
    let mut previous = Vec::new();
    previous.try_reserve_exact(inputs.len()).unwrap();
    for (position, input) in inputs.iter().enumerate() {
        previous.push(previous_transaction(
            &input.prevout_script,
            u8::try_from(position).unwrap(),
        ));
    }

    let mut unsigned = reserve_vec(64 + inputs.len() * 41 + outputs.len() * 43);
    append(&mut unsigned, &2u32.to_le_bytes());
    compact_size(&mut unsigned, inputs.len());
    for (position, input) in inputs.iter().enumerate() {
        let mut txid = sha256d(&previous[position]);
        if input.mismatch_outpoint_txid {
            txid[0] ^= 1;
        }
        append(&mut unsigned, &txid);
        append(&mut unsigned, &0u32.to_le_bytes());
        unsigned.push(0);
        append(&mut unsigned, &u32::MAX.to_le_bytes());
    }
    compact_size(&mut unsigned, outputs.len());
    for output in outputs {
        append(&mut unsigned, &9_000u64.to_le_bytes());
        compact_size(&mut unsigned, output.script_pubkey.len());
        append(&mut unsigned, &output.script_pubkey);
    }
    append(&mut unsigned, &0u32.to_le_bytes());

    let mut psbt = reserve_vec(unsigned.len() + inputs.len() * 320 + outputs.len() * 160);
    append(&mut psbt, b"psbt\xff");
    append_record(&mut psbt, &raw_record(0x00, &[], &unsigned));
    psbt.push(0);

    for (position, input) in inputs.iter().enumerate() {
        append_record(&mut psbt, &raw_record(0x00, &[], &previous[position]));
        if input.witness_utxo {
            let mut witness_utxo = reserve_vec(43);
            append(&mut witness_utxo, &10_000u64.to_le_bytes());
            compact_size(&mut witness_utxo, input.prevout_script.len());
            append(&mut witness_utxo, &input.prevout_script);
            append_record(&mut psbt, &raw_record(0x01, &[], &witness_utxo));
        }
        if let Some(script) = &input.witness_script {
            append_record(&mut psbt, &raw_record(0x05, &[], script));
        }
        for claim in &input.claims {
            append_record(&mut psbt, claim);
        }
        for record in &input.extra_records {
            append_record(&mut psbt, record);
        }
        psbt.push(0);
    }

    for output in outputs {
        for claim in &output.claims {
            append_record(&mut psbt, claim);
        }
        for record in &output.extra_records {
            append_record(&mut psbt, record);
        }
        psbt.push(0);
    }
    psbt
}

fn analyze_read_only<'a>(
    bytes: &'a [u8],
    descriptor: &DescriptorPair,
) -> DescriptorOwnershipAnalysis<'a> {
    let original = bytes.to_vec();
    let view = parse(bytes, InputSource::MicroSd).unwrap();
    let canonical_before = canonical_serialize(&view).unwrap();
    let result = analyze_descriptor_ownership(&view, descriptor).unwrap();
    assert_eq!(view.buffer(), bytes);
    assert_eq!(bytes, original);
    assert_eq!(canonical_before, canonical_serialize(&view).unwrap());
    result
}

fn assert_rejection(
    name: &str,
    bytes: &[u8],
    descriptor: &DescriptorPair,
    expected: SemanticCategory,
) {
    fixture_case(name, "named-rejection", &format!("{expected:?}"));
    assert_rejection_behavior(name, bytes, descriptor, expected);
}

fn assert_rejection_behavior(
    name: &str,
    bytes: &[u8],
    descriptor: &DescriptorPair,
    expected: SemanticCategory,
) {
    let original = bytes.to_vec();
    let view = parse(bytes, InputSource::MicroSd).unwrap();
    let canonical_before = canonical_serialize(&view).unwrap();
    drop(view);

    let attempt = catch_unwind(AssertUnwindSafe(|| {
        let parsed = parse(bytes, InputSource::MicroSd).unwrap();
        analyze_descriptor_ownership(&parsed, descriptor)
    }));
    let error = attempt
        .unwrap_or_else(|_| panic!("{name} panicked"))
        .unwrap_err();
    assert_eq!(error.category, expected, "{name}");
    assert_eq!(bytes, original, "{name}");

    let reparsed = parse(bytes, InputSource::MicroSd).unwrap();
    assert_eq!(
        canonical_before,
        canonical_serialize(&reparsed).unwrap(),
        "{name}"
    );
}

fn assert_measured_rejection(
    name: &str,
    bytes: &[u8],
    descriptor: &DescriptorPair,
    expected: SemanticCategory,
    expected_allocations: usize,
) {
    let original = bytes.to_vec();
    let view = parse(bytes, InputSource::MicroSd).unwrap();
    let canonical_before = canonical_serialize(&view).unwrap();
    reset_allocation_ledger();
    LEDGER_ENABLED.store(true, Ordering::SeqCst);
    let measured = catch_unwind(AssertUnwindSafe(|| {
        analyze_descriptor_ownership(&view, descriptor)
    }));
    LEDGER_ENABLED.store(false, Ordering::SeqCst);
    let error = measured
        .unwrap_or_else(|_| panic!("{name} panicked"))
        .unwrap_err();
    assert_eq!(error.category, expected, "{name}");
    assert_eq!(
        ALLOCATIONS_165.load(Ordering::Relaxed),
        expected_allocations,
        "{name}"
    );
    assert_eq!(
        BYTES_165.load(Ordering::Relaxed),
        expected_allocations * 165,
        "{name}"
    );
    assert_eq!(MAX_LIVE_165.load(Ordering::Relaxed), 1, "{name}");
    assert_eq!(LIVE_165.load(Ordering::Relaxed), 0, "{name}");
    assert_eq!(bytes, original, "{name}");
    assert_eq!(
        canonical_before,
        canonical_serialize(&view).unwrap(),
        "{name}"
    );
}

fn reset_allocation_ledger() {
    ALLOCATIONS_165.store(0, Ordering::Relaxed);
    BYTES_165.store(0, Ordering::Relaxed);
    LIVE_165.store(0, Ordering::Relaxed);
    MAX_LIVE_165.store(0, Ordering::Relaxed);
}

#[test]
fn descriptor_ownership_closed_inventory() {
    assert_eq!(
        sha256(b""),
        decode_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| line.starts_with("case: "))
            .count(),
        45
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| *line == "class: returned-fact")
            .count(),
        14
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| *line == "class: named-rejection")
            .count(),
        31
    );
    assert_eq!(qk_psbt::limits::MAX_CHILD_INDEX, 65_535);
    assert_eq!(qk_psbt::limits::MAX_CHILD_DERIVATIONS, 792);
    assert_eq!(132 * 6, 792);

    let descriptor = descriptor_pair();
    for (branch, index) in [(0, 0), (1, 0), (0, 65_535), (1, 65_535)] {
        let generated = derived(&descriptor, branch, index);
        let oracle = script_oracle(branch, index);
        assert_eq!(generated.witness_script.as_slice(), oracle.witness_script);
        assert_eq!(generated.script_pubkey.as_slice(), oracle.script_pubkey);
    }

    for (name, branch, witness_present, expected_label) in [
        ("R01", 0, true, "receive-input-witness-present"),
        ("R02", 0, false, "receive-input-witness-absent"),
        ("R03", 1, true, "change-input-witness-present"),
        ("R04", 1, false, "change-input-witness-absent"),
    ] {
        fixture_case(name, "returned-fact", expected_label);
        let bytes = build_psbt(
            &[owned_input(&descriptor, branch, 0, witness_present)],
            &[descriptor_output(&descriptor, 1, 0, 0)],
        );
        let analysis = analyze_read_only(&bytes, &descriptor);
        assert_eq!(analysis.wallet.inputs[0].branch, branch, "{name}");
        assert_eq!(analysis.wallet.inputs[0].index, 0, "{name}");
        assert!(analysis.candidate.inputs[0].witness_utxo_present, "{name}");
        assert_eq!(
            analysis.candidate.inputs[0].multisig_form.is_some(),
            witness_present,
            "{name}"
        );
        assert!(analysis.verified_inputs.iter().all(|input| {
            input.verified_signature_count == 0
                && input.status == VerifiedInputStatus::BelowThreshold
        }));
        assert_eq!(
            analysis.aggregate_status,
            VerifiedAggregateStatus::AllInputsBelowThreshold
        );
        if name == "R02" {
            let view = parse(&bytes, InputSource::MicroSd).unwrap();
            let error = analyze_and_verify_signatures(&view).unwrap_err();
            assert_eq!(error.category, SemanticCategory::MissingWitnessScript);
        }
    }

    for (name, local_roles, foreign, branch, expected, expected_label) in [
        (
            "R05",
            0,
            false,
            1,
            OutputOwnership::NotProvenOwned,
            "output-no-metadata-unproven",
        ),
        (
            "R06",
            1,
            false,
            1,
            OutputOwnership::NotProvenOwned,
            "output-one-role-unproven",
        ),
        (
            "R07",
            2,
            false,
            1,
            OutputOwnership::NotProvenOwned,
            "output-two-role-unproven",
        ),
        (
            "R08",
            0,
            true,
            1,
            OutputOwnership::NotProvenOwned,
            "output-foreign-only-unproven",
        ),
        (
            "R09",
            3,
            false,
            1,
            OutputOwnership::ProvenChange(0),
            "output-complete-change",
        ),
        (
            "R10",
            3,
            false,
            0,
            OutputOwnership::ProvenSelfTransfer(0),
            "output-complete-receive-self-transfer",
        ),
        (
            "R11",
            3,
            true,
            1,
            OutputOwnership::ProvenChange(0),
            "output-complete-plus-foreign-change",
        ),
    ] {
        fixture_case(name, "returned-fact", expected_label);
        let mut output = descriptor_output(&descriptor, branch, 0, local_roles);
        if foreign {
            output.extra_records.push(foreign_claim(0x02));
        }
        let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
        let analysis = analyze_read_only(&bytes, &descriptor);
        assert_eq!(analysis.wallet.outputs[0], expected, "{name}");
    }

    fixture_case("R12", "returned-fact", "multi-input-output-mixed");
    let bytes = build_psbt(
        &[
            owned_input(&descriptor, 0, 0, true),
            owned_input(&descriptor, 1, 0, false),
        ],
        &[
            descriptor_output(&descriptor, 1, 0, 3),
            descriptor_output(&descriptor, 0, 0, 3),
        ],
    );
    let analysis = analyze_read_only(&bytes, &descriptor);
    assert_eq!(analysis.wallet.inputs.len(), 2);
    assert_eq!(
        analysis.wallet.outputs,
        [
            OutputOwnership::ProvenChange(0),
            OutputOwnership::ProvenSelfTransfer(0)
        ]
    );

    fixture_case("R13", "returned-fact", "max-child-index-65535");
    let bytes = build_psbt(
        &[owned_input(&descriptor, 1, 65_535, true)],
        &[descriptor_output(&descriptor, 0, 65_535, 3)],
    );
    let analysis = analyze_read_only(&bytes, &descriptor);
    assert_eq!(analysis.wallet.inputs[0].index, 65_535);
    assert_eq!(
        analysis.wallet.outputs[0],
        OutputOwnership::ProvenSelfTransfer(65_535)
    );

    fixture_case(
        "R14",
        "returned-fact",
        "max-100-input-32-output-allocation-ledger",
    );
    let mut max_inputs = Vec::new();
    max_inputs.try_reserve_exact(100).unwrap();
    for position in 0..100 {
        max_inputs.push(owned_input(
            &descriptor,
            u32::try_from(position & 1).unwrap(),
            0,
            true,
        ));
    }
    let mut max_outputs = Vec::new();
    max_outputs.try_reserve_exact(32).unwrap();
    for position in 0..32 {
        max_outputs.push(descriptor_output(
            &descriptor,
            u32::try_from(position & 1).unwrap(),
            0,
            3,
        ));
    }
    let max_bytes = build_psbt(&max_inputs, &max_outputs);
    let max_original = max_bytes.clone();
    let max_view = parse(&max_bytes, InputSource::MicroSd).unwrap();
    let max_canonical = canonical_serialize(&max_view).unwrap();
    reset_allocation_ledger();
    LEDGER_ENABLED.store(true, Ordering::SeqCst);
    let measured = catch_unwind(AssertUnwindSafe(|| {
        analyze_descriptor_ownership(&max_view, &descriptor)
    }));
    LEDGER_ENABLED.store(false, Ordering::SeqCst);
    let max_analysis = measured.unwrap().unwrap();
    assert_eq!(max_analysis.wallet.inputs.len(), 100);
    assert_eq!(max_analysis.wallet.outputs.len(), 32);
    assert_eq!(ALLOCATIONS_165.load(Ordering::Relaxed), 792);
    assert_eq!(BYTES_165.load(Ordering::Relaxed), 130_680);
    assert_eq!(MAX_LIVE_165.load(Ordering::Relaxed), 1);
    assert_eq!(LIVE_165.load(Ordering::Relaxed), 0);
    assert_eq!(max_bytes, max_original);
    assert_eq!(max_canonical, canonical_serialize(&max_view).unwrap());

    let base_output = || descriptor_output(&descriptor, 1, 0, 3);

    let equal_fingerprint = descriptor_pair_named("EQUAL_FINGERPRINT");
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[base_output()]);
    assert_rejection(
        "E01",
        &bytes,
        &equal_fingerprint,
        SemanticCategory::AmbiguousDescriptorFingerprints,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.clear();
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E02",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationRecordCount,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.truncate(1);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E03",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationRecordCount,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.push(claim_record(
        0x06,
        &authority_key(0),
        FP[2],
        &exact_path(0, 0),
    ));
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E04",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationRecordCount,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_key(&mut input.claims[0], &[0x04; 65]);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E05",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationPublicKey,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_path(&mut input.claims[0], FP[0], &[]);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E06",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationPath,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_path(
        &mut input.claims[0],
        FP[0],
        &[
            BIP48_PREFIX[0],
            BIP48_PREFIX[1],
            BIP48_PREFIX[2],
            BIP48_PREFIX[3],
            0,
        ],
    );
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E07",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationPath,
    );

    for (name, component, value) in [
        ("E08", 0, HARDENED | 49),
        ("E09", 1, HARDENED | 1),
        ("E10", 2, HARDENED | 1),
        ("E11", 3, HARDENED | 3),
    ] {
        let mut input = owned_input(&descriptor, 0, 0, true);
        let mut path = exact_path(0, 0);
        path[component] = value;
        set_claim_path(&mut input.claims[0], FP[0], &path);
        let bytes = build_psbt(&[input], &[base_output()]);
        assert_rejection(
            name,
            &bytes,
            &descriptor,
            SemanticCategory::DescriptorDerivationPath,
        );
    }

    let mut input = owned_input(&descriptor, 0, 0, true);
    for (role, claim) in input.claims.iter_mut().enumerate() {
        set_claim_path(claim, FP[role], &exact_path(2, 0));
    }
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E12",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorBranchOutOfRange,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    for (role, claim) in input.claims.iter_mut().enumerate() {
        set_claim_path(claim, FP[role], &exact_path(0, 65_536));
    }
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E13",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorChildIndexOutOfRange,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_fingerprint(&mut input.claims[1], FOREIGN_FP);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E14",
        &bytes,
        &descriptor,
        SemanticCategory::ForeignInputDescriptorRole,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_fingerprint(&mut input.claims[1], FP[0]);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E15",
        &bytes,
        &descriptor,
        SemanticCategory::DuplicateDescriptorRole,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_path(&mut input.claims[1], FP[1], &exact_path(1, 0));
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E16",
        &bytes,
        &descriptor,
        SemanticCategory::MixedDescriptorCoordinates,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_path(&mut input.claims[1], FP[1], &exact_path(0, 1));
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E17",
        &bytes,
        &descriptor,
        SemanticCategory::MixedDescriptorCoordinates,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    set_claim_key(&mut input.claims[0], &route_keys(1, 0)[0]);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E18",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationKeyMismatch,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    for (role, claim) in input.claims.iter_mut().enumerate() {
        set_claim_path(claim, FP[role], &exact_path(1, 0));
    }
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E19",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationKeyMismatch,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.witness_script = Some(script_oracle(1, 0).witness_script);
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E20",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorWitnessScriptMismatch,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.prevout_script = script_oracle(1, 0).script_pubkey;
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E21",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorPrevoutScriptMismatch,
    );

    let mut output = descriptor_output(&descriptor, 1, 0, 3);
    set_claim_fingerprint(&mut output.claims[1], FP[0]);
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
    assert_rejection(
        "E22",
        &bytes,
        &descriptor,
        SemanticCategory::DuplicateDescriptorRole,
    );

    let mut output = descriptor_output(&descriptor, 1, 0, 3);
    set_claim_path(&mut output.claims[1], FP[1], &exact_path(0, 0));
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
    assert_rejection(
        "E23",
        &bytes,
        &descriptor,
        SemanticCategory::MixedDescriptorCoordinates,
    );

    let mut output = descriptor_output(&descriptor, 1, 0, 3);
    set_claim_path(&mut output.claims[1], FP[1], &exact_path(1, 1));
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
    assert_rejection(
        "E24",
        &bytes,
        &descriptor,
        SemanticCategory::MixedDescriptorCoordinates,
    );

    let mut output = descriptor_output(&descriptor, 1, 0, 3);
    set_claim_key(&mut output.claims[0], &route_keys(0, 0)[0]);
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
    assert_rejection(
        "E25",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationKeyMismatch,
    );

    let mut output = descriptor_output(&descriptor, 0, 0, 3);
    output.script_pubkey = script_oracle(1, 0).script_pubkey;
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
    assert_rejection(
        "E26",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorOutputScriptMismatch,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.clear();
    input.extra_records.push(raw_record(0x07, &[], &[]));
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E27",
        &bytes,
        &descriptor,
        SemanticCategory::UnsupportedFinalScriptFields,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.clear();
    input.extra_records.push(raw_record(0x04, &[], &[0x00]));
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E28",
        &bytes,
        &descriptor,
        SemanticCategory::UnsupportedRedeemScriptRoute,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.clear();
    input
        .extra_records
        .push(raw_record(0x03, &[], &2u32.to_le_bytes()));
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E29",
        &bytes,
        &descriptor,
        SemanticCategory::UnsupportedSighash,
    );

    let mut input = owned_input(&descriptor, 0, 0, true);
    input.claims.clear();
    input.mismatch_outpoint_txid = true;
    let bytes = build_psbt(&[input], &[base_output()]);
    assert_rejection(
        "E30",
        &bytes,
        &descriptor,
        SemanticCategory::PrevTxIdMismatch,
    );

    let mut output = descriptor_output(&descriptor, 1, 0, 1);
    set_claim_path(
        &mut output.claims[0],
        FP[0],
        &[
            HARDENED | 49,
            BIP48_PREFIX[1],
            BIP48_PREFIX[2],
            BIP48_PREFIX[3],
            1,
            0,
        ],
    );
    let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
    assert_rejection(
        "E31",
        &bytes,
        &descriptor,
        SemanticCategory::DescriptorDerivationPath,
    );

    let mut coherent_partial_cases = 0usize;
    for local_roles in [1, 2] {
        let bytes = build_psbt(
            &[owned_input(&descriptor, 0, 0, true)],
            &[descriptor_output(&descriptor, 1, 0, local_roles)],
        );
        let view = parse(&bytes, InputSource::MicroSd).unwrap();
        reset_allocation_ledger();
        LEDGER_ENABLED.store(true, Ordering::SeqCst);
        let measured = catch_unwind(AssertUnwindSafe(|| {
            analyze_descriptor_ownership(&view, &descriptor)
        }));
        LEDGER_ENABLED.store(false, Ordering::SeqCst);
        let analysis = measured.unwrap().unwrap();
        assert_eq!(analysis.wallet.outputs[0], OutputOwnership::NotProvenOwned);
        assert_eq!(ALLOCATIONS_165.load(Ordering::Relaxed), 12);
        assert_eq!(BYTES_165.load(Ordering::Relaxed), 1_980);
        assert_eq!(MAX_LIVE_165.load(Ordering::Relaxed), 1);
        assert_eq!(LIVE_165.load(Ordering::Relaxed), 0);
        coherent_partial_cases += 1;
    }
    assert_eq!(coherent_partial_cases, 2);

    let mut partial_contradiction_cases = 0usize;
    for (name, local_roles, role, wrong_key) in [
        ("one-role-wrong-key", 1, 0, route_keys(0, 0)[0]),
        ("two-role-wrong-key", 2, 1, route_keys(0, 0)[1]),
        (
            "one-role-off-curve-key",
            1,
            0,
            decode_hex("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
        ),
    ] {
        let mut output = descriptor_output(&descriptor, 1, 0, local_roles);
        set_claim_key(&mut output.claims[role], &wrong_key);
        let bytes = build_psbt(&[owned_input(&descriptor, 0, 0, true)], &[output]);
        assert_measured_rejection(
            name,
            &bytes,
            &descriptor,
            SemanticCategory::DescriptorDerivationKeyMismatch,
            12,
        );
        partial_contradiction_cases += 1;
    }
    assert_eq!(partial_contradiction_cases, 3);

    let invalid_signature = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
    let mut input = owned_input(&descriptor, 0, 0, true);
    input
        .extra_records
        .push(raw_record(0x02, &route_keys(0, 0)[0], &invalid_signature));
    let mut output = descriptor_output(&descriptor, 1, 0, 1);
    set_claim_key(&mut output.claims[0], &route_keys(0, 0)[0]);
    let bytes = build_psbt(&[input], &[output]);
    assert_rejection_behavior(
        "invalid-signature-before-output-contradiction",
        &bytes,
        &descriptor,
        SemanticCategory::SignatureVerificationFailed,
    );

    let mutation_seed = build_psbt(
        &[owned_input(&descriptor, 0, 0, true)],
        &[descriptor_output(&descriptor, 1, 0, 3)],
    );
    assert!(mutation_seed.len() <= 4_096);
    let mut mutation_count = 0usize;
    for index in 0..mutation_seed.len() {
        for mask in [0x01u8, 0x80] {
            let mut mutated = mutation_seed.clone();
            mutated[index] ^= mask;
            let original = mutated.clone();
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                if let Ok(view) = parse(&mutated, InputSource::MicroSd) {
                    let canonical_before = canonical_serialize(&view).unwrap();
                    let _ = analyze_descriptor_ownership(&view, &descriptor);
                    assert_eq!(canonical_before, canonical_serialize(&view).unwrap());
                }
            }));
            assert!(attempt.is_ok(), "mutation index {index} mask {mask:#04x}");
            assert_eq!(mutated, original);
            mutation_count += 1;
        }
    }
    assert_eq!(mutation_count, mutation_seed.len() * 2);
}
