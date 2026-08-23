//! M6 semantic-subset analyzer tests (QK-DEC-037/038/039). Locally
//! authored non-fundable fixtures only; no external vectors. The
//! test-local SHA-256 below is an independent oracle implementation,
//! cross-checked against hard-coded digests.

use qk_psbt::{
    analyze_semantic_subset, canonical_serialize, parse, InputSignatureStatus, InputSource,
    ScriptToken, ScriptTokens, SemanticCategory, SemanticError,
};

const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// Hard-coded double-SHA256 of the fixed legacy oracle prevtx (and of
/// the witness-stripped serialization of the witness oracle prevtx).
const ORACLE_TXID: [u8; 32] = [
    0x15, 0x8c, 0x8f, 0x2e, 0xb8, 0x89, 0xe0, 0x46, 0x6a, 0xaf, 0xd5, 0xbb, 0x94, 0xb9, 0xf4, 0xf6,
    0x8d, 0x13, 0x71, 0x3b, 0x28, 0x33, 0x49, 0xef, 0x64, 0x51, 0x07, 0x95, 0xed, 0x75, 0xd2, 0x17,
];

/// Hard-coded double-SHA256 of the FULL witness serialization of the
/// witness oracle prevtx (its wtxid) — must never match an outpoint.
const ORACLE_WTXID: [u8; 32] = [
    0xfe, 0x0b, 0xe6, 0x00, 0x46, 0x1a, 0xd3, 0x32, 0x60, 0x9d, 0xea, 0xaa, 0xb5, 0x3d, 0xdf, 0xfe,
    0x89, 0x40, 0xe6, 0x1f, 0xb9, 0xcb, 0xd3, 0x34, 0x56, 0xf0, 0x24, 0x2f, 0x14, 0x35, 0xb0, 0x3e,
];

/// BIP146 low-S inclusive bound, big-endian.
const LOW_S_MAX: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

// ---------------------------------------------------------------
// Test-local independent SHA-256 oracle (FIPS 180-4 by the book).
// ---------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn oracle_sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut data = msg.to_vec();
    let bitlen = (msg.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bitlen.to_be_bytes());
    for block in data.chunks(64) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, v) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn oracle_sha256d(msg: &[u8]) -> [u8; 32] {
    oracle_sha256(&oracle_sha256(msg))
}

// ---------------------------------------------------------------
// Fixture builders (locally authored, non-fundable).
// ---------------------------------------------------------------

fn cs(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn rec(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = cs(key.len() as u64);
    v.extend_from_slice(key);
    v.extend_from_slice(&cs(value.len() as u64));
    v.extend_from_slice(value);
    v
}

fn unsigned_tx(ins: &[([u8; 32], u32)], outs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    v.extend_from_slice(&cs(ins.len() as u64));
    for (txid, vout) in ins {
        v.extend_from_slice(txid);
        v.extend_from_slice(&vout.to_le_bytes());
        v.push(0x00); // empty scriptSig
        v.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    }
    v.extend_from_slice(&cs(outs.len() as u64));
    for (amount, script) in outs {
        v.extend_from_slice(&amount.to_le_bytes());
        v.extend_from_slice(&cs(script.len() as u64));
        v.extend_from_slice(script);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// Legacy prevtx: version 1, `n_inputs` inputs (inner txid `[salt;
/// 32]`, one shared scriptSig), given outputs, locktime 0.
fn prevtx_legacy(salt: u8, n_inputs: usize, scriptsig: &[u8], outs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.extend_from_slice(&cs(n_inputs as u64));
    for _ in 0..n_inputs {
        v.extend_from_slice(&[salt; 32]);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&cs(scriptsig.len() as u64));
        v.extend_from_slice(scriptsig);
        v.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    }
    v.extend_from_slice(&cs(outs.len() as u64));
    for (amount, script) in outs {
        v.extend_from_slice(&amount.to_le_bytes());
        v.extend_from_slice(&cs(script.len() as u64));
        v.extend_from_slice(script);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// Witness prevtx from the same parts: returns (full serialization,
/// witness-stripped serialization). One witness stack per input.
fn prevtx_witness(
    salt: u8,
    outs: &[(u64, Vec<u8>)],
    stacks: &[Vec<Vec<u8>>],
) -> (Vec<u8>, Vec<u8>) {
    let stripped = prevtx_legacy(salt, stacks.len(), &[], outs);
    let mut full = 1u32.to_le_bytes().to_vec();
    full.extend_from_slice(&[0x00, 0x01]);
    full.extend_from_slice(&stripped[4..stripped.len() - 4]);
    for stack in stacks {
        full.extend_from_slice(&cs(stack.len() as u64));
        for item in stack {
            full.extend_from_slice(&cs(item.len() as u64));
            full.extend_from_slice(item);
        }
    }
    full.extend_from_slice(&stripped[stripped.len() - 4..]);
    (full, stripped)
}

fn psbt(unsigned: &[u8], input_maps: &[Vec<Vec<u8>>], n_outputs: usize) -> Vec<u8> {
    let mut v = vec![0x70, 0x73, 0x62, 0x74, 0xff];
    v.extend_from_slice(&rec(&[0x00], unsigned));
    v.push(0x00);
    for records in input_maps {
        for r in records {
            v.extend_from_slice(r);
        }
        v.push(0x00);
    }
    v.extend(std::iter::repeat_n(0x00, n_outputs));
    v
}

fn r_nwutxo(tx: &[u8]) -> Vec<u8> {
    rec(&[0x00], tx)
}

fn r_wutxo(amount: u64, script: &[u8]) -> Vec<u8> {
    let mut v = amount.to_le_bytes().to_vec();
    v.extend_from_slice(&cs(script.len() as u64));
    v.extend_from_slice(script);
    rec(&[0x01], &v)
}

fn r_sig(pubkey: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut key = vec![0x02];
    key.extend_from_slice(pubkey);
    rec(&key, sig)
}

fn r_sighash(v: u32) -> Vec<u8> {
    rec(&[0x03], &v.to_le_bytes())
}

fn r_wscript(s: &[u8]) -> Vec<u8> {
    rec(&[0x05], s)
}

fn der(r: &[u8], s: &[u8], trailing: u8) -> Vec<u8> {
    let mut v = vec![0x30, (4 + r.len() + s.len()) as u8, 0x02, r.len() as u8];
    v.extend_from_slice(r);
    v.push(0x02);
    v.push(s.len() as u8);
    v.extend_from_slice(s);
    v.push(trailing);
    v
}

fn good_sig() -> Vec<u8> {
    der(&[0x01], &[0x01], 0x01)
}

fn pk(i: u8) -> [u8; 33] {
    let mut k = [i; 33];
    k[0] = 0x02;
    k
}

fn wscript(m: u8, keys: &[[u8; 33]]) -> Vec<u8> {
    let mut v = vec![0x50 + m];
    for k in keys {
        v.push(0x21);
        v.extend_from_slice(k);
    }
    v.push(0x50 + keys.len() as u8);
    v.push(0xae);
    v
}

fn spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x14];
    v.extend_from_slice(&[0xaa; 20]);
    v
}

/// Single-input single-output PSBT over the given prevtx (spending
/// `vout`), with extra input-map records appended.
fn simple(prev: &[u8], txid: [u8; 32], vout: u32, extra: &[Vec<u8>]) -> Vec<u8> {
    let unsigned = unsigned_tx(&[(txid, vout)], &[(90_000, spk())]);
    let mut records = vec![r_nwutxo(prev)];
    records.extend_from_slice(extra);
    psbt(&unsigned, &[records], 1)
}

fn base_prev() -> (Vec<u8>, [u8; 32]) {
    let prev = prevtx_legacy(0x11, 1, &[], &[(100_000, spk())]);
    let txid = oracle_sha256d(&prev);
    (prev, txid)
}

fn analyze_err(bytes: &[u8]) -> SemanticError {
    let view = parse(bytes, InputSource::MicroSd).expect("fixture must parse");
    analyze_semantic_subset(&view).expect_err("expected semantic rejection")
}

fn assert_ok(bytes: &[u8]) {
    let view = parse(bytes, InputSource::MicroSd).expect("fixture must parse");
    analyze_semantic_subset(&view).expect("expected semantic acceptance");
}

// ---------------------------------------------------------------
// txid identity: oracles, wire order, witness stripping.
// ---------------------------------------------------------------

#[test]
fn oracle_legacy_and_witness_txid_hardcoded() {
    let (prev, txid) = base_prev();
    // Independent oracle cross-check: the legacy prevtx used by
    // base_prev is NOT the oracle prevtx (different script); build
    // the exact oracle transactions here.
    let oracle_legacy = prevtx_legacy(0x11, 1, &[], &[(100_000, vec![0x51, 0x52, 0x53, 0x54])]);
    assert_eq!(oracle_sha256d(&oracle_legacy), ORACLE_TXID);
    let (oracle_wit_full, oracle_wit_stripped) = prevtx_witness(
        0x11,
        &[(100_000, vec![0x51, 0x52, 0x53, 0x54])],
        &[vec![vec![0xbe, 0xef]]],
    );
    assert_eq!(oracle_sha256d(&oracle_wit_stripped), ORACLE_TXID);
    assert_eq!(oracle_sha256d(&oracle_wit_full), ORACLE_WTXID);
    assert_ne!(ORACLE_TXID, ORACLE_WTXID);
    // The analyzer accepts the oracle txid for both serializations.
    assert_ok(&simple(&oracle_legacy, ORACLE_TXID, 0, &[]));
    assert_ok(&simple(&oracle_wit_full, ORACLE_TXID, 0, &[]));
    // And the base fixture, via the same oracle.
    assert_ok(&simple(&prev, txid, 0, &[]));
}

#[test]
fn wtxid_is_not_accepted_as_outpoint() {
    let (full, _) = prevtx_witness(
        0x11,
        &[(100_000, vec![0x51, 0x52, 0x53, 0x54])],
        &[vec![vec![0xbe, 0xef]]],
    );
    let e = analyze_err(&simple(&full, ORACLE_WTXID, 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxIdMismatch);
    assert_eq!(e.input_index, Some(0));
}

#[test]
fn txid_wire_order_not_display_reversed() {
    let (prev, txid) = base_prev();
    let mut reversed = txid;
    reversed.reverse();
    let e = analyze_err(&simple(&prev, reversed, 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxIdMismatch);
}

#[test]
fn witness_only_mutation_preserves_txid_acceptance() {
    let outs = [(100_000u64, spk())];
    let (full_a, stripped) = prevtx_witness(0x33, &outs, &[vec![vec![0xbe, 0xef]]]);
    let (full_b, stripped_b) = prevtx_witness(0x33, &outs, &[vec![vec![0x01; 40]]]);
    assert_eq!(stripped, stripped_b);
    assert_ne!(full_a, full_b);
    let txid = oracle_sha256d(&stripped);
    assert_ok(&simple(&full_a, txid, 0, &[]));
    assert_ok(&simple(&full_b, txid, 0, &[]));
}

// ---------------------------------------------------------------
// Prevout selection, vout range, multi-input totals.
// ---------------------------------------------------------------

#[test]
fn first_and_last_vout_selection() {
    let outs = [(111u64, spk()), (222u64, spk()), (333u64, spk())];
    let prev = prevtx_legacy(0x44, 1, &[], &outs);
    let txid = oracle_sha256d(&prev);
    for (vout, expected) in [(0u32, 111u64), (2, 333)] {
        let unsigned = unsigned_tx(&[(txid, vout)], &[(1, spk())]);
        let b = psbt(&unsigned, &[vec![r_nwutxo(&prev)]], 1);
        let view = parse(&b, InputSource::MicroSd).unwrap();
        let c = analyze_semantic_subset(&view).unwrap();
        assert_eq!(c.inputs[0].prevout_amount, expected);
        assert_eq!(c.inputs[0].prevout_script_pubkey, spk().as_slice());
        assert_eq!(c.inputs[0].outpoint_vout, vout);
    }
}

#[test]
fn vout_out_of_range_rejected() {
    let (prev, txid) = base_prev();
    let e = analyze_err(&simple(&prev, txid, 1, &[]));
    assert_eq!(e.category, SemanticCategory::VoutOutOfRange);
    assert_eq!(e.input_index, Some(0));
}

#[test]
fn multi_input_totals_and_fee() {
    let prev_a = prevtx_legacy(0x21, 1, &[], &[(1_000, spk()), (2_000, spk())]);
    let prev_b = prevtx_legacy(0x22, 1, &[], &[(5_000, spk())]);
    let txid_a = oracle_sha256d(&prev_a);
    let txid_b = oracle_sha256d(&prev_b);
    let unsigned = unsigned_tx(&[(txid_a, 0), (txid_a, 1), (txid_b, 0)], &[(7_000, spk())]);
    let b = psbt(
        &unsigned,
        &[
            vec![r_nwutxo(&prev_a)],
            vec![r_nwutxo(&prev_a)],
            vec![r_nwutxo(&prev_b)],
        ],
        1,
    );
    let view = parse(&b, InputSource::MicroSd).unwrap();
    let c = analyze_semantic_subset(&view).unwrap();
    assert_eq!(c.total_input_amount, 8_000);
    assert_eq!(c.total_output_amount, 7_000);
    assert_eq!(c.fee, 1_000);
    assert_eq!(c.inputs.len(), 3);
    assert_eq!(c.inputs[1].prevout_amount, 2_000);
}

// ---------------------------------------------------------------
// witness_utxo equality (QK-DEC-032), missing/mismatched prevtx.
// ---------------------------------------------------------------

#[test]
fn witness_utxo_equal_accepted() {
    let (prev, txid) = base_prev();
    let b = simple(&prev, txid, 0, &[r_wutxo(100_000, &spk())]);
    let view = parse(&b, InputSource::MicroSd).unwrap();
    let c = analyze_semantic_subset(&view).unwrap();
    assert!(c.inputs[0].witness_utxo_present);
}

#[test]
fn witness_utxo_amount_mismatch_rejected() {
    let (prev, txid) = base_prev();
    let e = analyze_err(&simple(&prev, txid, 0, &[r_wutxo(99_999, &spk())]));
    assert_eq!(e.category, SemanticCategory::WitnessUtxoMismatch);
}

#[test]
fn witness_utxo_script_mismatch_rejected() {
    let (prev, txid) = base_prev();
    let mut other = spk();
    other[2] ^= 0xff;
    let e = analyze_err(&simple(&prev, txid, 0, &[r_wutxo(100_000, &other)]));
    assert_eq!(e.category, SemanticCategory::WitnessUtxoMismatch);
}

#[test]
fn missing_prevtx_rejected() {
    let (_, txid) = base_prev();
    let unsigned = unsigned_tx(&[(txid, 0)], &[(1, spk())]);
    let b = psbt(&unsigned, &[vec![]], 1);
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::MissingPrevTx);
    assert_eq!(e.input_index, Some(0));
}

#[test]
fn prevtx_txid_mismatch_rejected() {
    let (prev, _) = base_prev();
    let e = analyze_err(&simple(&prev, [0xab; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxIdMismatch);
}

// ---------------------------------------------------------------
// Prevtx malformation: truncation, trailing, CompactSize, zero outs.
// ---------------------------------------------------------------

#[test]
fn prevtx_truncated_and_trailing_rejected() {
    let (prev, txid) = base_prev();
    let truncated = &prev[..prev.len() - 2];
    let e = analyze_err(&simple(truncated, txid, 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxMalformed);
    let mut trailing = prev.clone();
    trailing.push(0x00);
    let e = analyze_err(&simple(&trailing, txid, 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxMalformed);
}

#[test]
fn prevtx_nonminimal_compact_size_rejected() {
    let (prev, txid) = base_prev();
    // Replace the one-byte vin count 0x01 with non-minimal fd 01 00.
    let mut bad = prev[..4].to_vec();
    bad.extend_from_slice(&[0xfd, 0x01, 0x00]);
    bad.extend_from_slice(&prev[5..]);
    let e = analyze_err(&simple(&bad, txid, 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxMalformed);
}

#[test]
fn prevtx_zero_outputs_rejected() {
    let prev = prevtx_legacy(0x55, 1, &[], &[]);
    let txid = oracle_sha256d(&prev);
    let e = analyze_err(&simple(&prev, txid, 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxMalformed);
}

// ---------------------------------------------------------------
// Duplicate outpoints before prevtx work.
// ---------------------------------------------------------------

#[test]
fn duplicate_outpoint_rejected_before_prevtx_parse() {
    let unsigned = unsigned_tx(&[([0xcd; 32], 7), ([0xcd; 32], 7)], &[(1, spk())]);
    // Both input maps carry garbage prevtx values that would fail
    // parsing; the duplicate outpoint must win.
    let garbage = rec(&[0x00], &[0xde, 0xad]);
    let b = psbt(&unsigned, &[vec![garbage.clone()], vec![garbage]], 1);
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::DuplicateOutpoint);
    assert_eq!(e.input_index, Some(1));
}

// ---------------------------------------------------------------
// QK-DEC-039 caps: exact bound accepted, bound+1 rejected.
// ---------------------------------------------------------------

#[test]
fn prevtx_input_cap_exact_and_exceeded() {
    let ok = prevtx_legacy(0x61, 8192, &[], &[(100_000, spk())]);
    assert_ok(&simple(&ok, oracle_sha256d(&ok), 0, &[]));
    let over = prevtx_legacy(0x61, 8193, &[], &[(100_000, spk())]);
    // Cap categories fire before any txid work, so the outpoint txid
    // can be arbitrary.
    let e = analyze_err(&simple(&over, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxTooManyInputs);
}

#[test]
fn prevtx_output_cap_exact_and_exceeded() {
    let outs_ok: Vec<(u64, Vec<u8>)> = (0..8192).map(|_| (1u64, Vec::new())).collect();
    let ok = prevtx_legacy(0x62, 1, &[], &outs_ok);
    let unsigned = unsigned_tx(&[(oracle_sha256d(&ok), 8191)], &[(1, spk())]);
    let b = psbt(&unsigned, &[vec![r_nwutxo(&ok)]], 1);
    assert_ok(&b);
    let outs_over: Vec<(u64, Vec<u8>)> = (0..8193).map(|_| (1u64, Vec::new())).collect();
    let over = prevtx_legacy(0x62, 1, &[], &outs_over);
    let e = analyze_err(&simple(&over, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxTooManyOutputs);
}

#[test]
fn prevtx_script_cap_exact_and_exceeded() {
    let ok = prevtx_legacy(0x63, 1, &[0x00; 10_000], &[(100_000, spk())]);
    assert_ok(&simple(&ok, oracle_sha256d(&ok), 0, &[]));
    let over = prevtx_legacy(0x63, 1, &[0x00; 10_001], &[(100_000, spk())]);
    let e = analyze_err(&simple(&over, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxScriptTooLong);
    // Output-side scriptPubKey cap: an unselected oversized output.
    let over_out = prevtx_legacy(0x63, 1, &[], &[(1_000, spk()), (1, vec![0x00; 10_001])]);
    let e = analyze_err(&simple(&over_out, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxScriptTooLong);
}

#[test]
fn prevtx_witness_item_caps() {
    let outs = [(100_000u64, spk())];
    let stack_ok: Vec<Vec<u8>> = (0..1000).map(|_| Vec::new()).collect();
    let (full, stripped) = prevtx_witness(0x64, &outs, &[stack_ok]);
    assert_ok(&simple(&full, oracle_sha256d(&stripped), 0, &[]));
    let stack_over: Vec<Vec<u8>> = (0..1001).map(|_| Vec::new()).collect();
    let (full, _) = prevtx_witness(0x64, &outs, &[stack_over]);
    let e = analyze_err(&simple(&full, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxTooManyWitnessItems);
    let (full, stripped) = prevtx_witness(0x64, &outs, &[vec![vec![0xcc; 10_000]]]);
    assert_ok(&simple(&full, oracle_sha256d(&stripped), 0, &[]));
    let (full, _) = prevtx_witness(0x64, &outs, &[vec![vec![0xcc; 10_001]]]);
    let e = analyze_err(&simple(&full, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxWitnessItemTooLong);
}

#[test]
fn prevtx_witness_flag_and_superfluous() {
    let outs = [(1_000u64, spk())];
    let (full, _) = prevtx_witness(0x65, &outs, &[vec![vec![0xbe]]]);
    let mut bad_flag = full.clone();
    bad_flag[5] = 0x02; // flag byte
    let e = analyze_err(&simple(&bad_flag, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxWitnessUnsupportedFlag);
    // All-empty witness stacks: superfluous witness serialization.
    let (empty_full, _) = prevtx_witness(0x65, &outs, &[vec![]]);
    let e = analyze_err(&simple(&empty_full, [0; 32], 0, &[]));
    assert_eq!(e.category, SemanticCategory::PrevTxWitnessSuperfluous);
}

// ---------------------------------------------------------------
// MoneyRange, totals, fee.
// ---------------------------------------------------------------

#[test]
fn money_range_bounds_and_running_total() {
    let at_max = prevtx_legacy(0x71, 1, &[], &[(MAX_MONEY, spk())]);
    let txid = oracle_sha256d(&at_max);
    let unsigned = unsigned_tx(&[(txid, 0)], &[(MAX_MONEY, spk())]);
    let b = psbt(&unsigned, &[vec![r_nwutxo(&at_max)]], 1);
    let view = parse(&b, InputSource::MicroSd).unwrap();
    let c = analyze_semantic_subset(&view).unwrap();
    assert_eq!(c.fee, 0);
    let over = prevtx_legacy(0x72, 1, &[], &[(MAX_MONEY + 1, spk())]);
    let e = analyze_err(&simple(&over, oracle_sha256d(&over), 0, &[]));
    assert_eq!(e.category, SemanticCategory::MoneyRangeExceeded);
    // Two inputs individually at MAX_MONEY: the running input total
    // exceeds MoneyRange at the second input.
    let a = prevtx_legacy(0x73, 1, &[], &[(MAX_MONEY, spk())]);
    let b2 = prevtx_legacy(0x74, 1, &[], &[(MAX_MONEY, spk())]);
    let unsigned = unsigned_tx(
        &[(oracle_sha256d(&a), 0), (oracle_sha256d(&b2), 0)],
        &[(1, spk())],
    );
    let bytes = psbt(&unsigned, &[vec![r_nwutxo(&a)], vec![r_nwutxo(&b2)]], 1);
    let e = analyze_err(&bytes);
    assert_eq!(e.category, SemanticCategory::MoneyRangeExceeded);
    assert_eq!(e.input_index, Some(1));
}

#[test]
fn unsigned_output_money_range_and_negative_fee() {
    let (prev, txid) = base_prev();
    let unsigned = unsigned_tx(&[(txid, 0)], &[(MAX_MONEY + 1, spk())]);
    let e = analyze_err(&psbt(&unsigned, &[vec![r_nwutxo(&prev)]], 1));
    assert_eq!(e.category, SemanticCategory::MoneyRangeExceeded);
    assert_eq!(e.input_index, None);
    let unsigned = unsigned_tx(&[(txid, 0)], &[(150_000, spk())]);
    let e = analyze_err(&psbt(&unsigned, &[vec![r_nwutxo(&prev)]], 1));
    assert_eq!(e.category, SemanticCategory::NegativeFee);
}

// ---------------------------------------------------------------
// Sighash policy.
// ---------------------------------------------------------------

#[test]
fn sighash_matrix() {
    let (prev, txid) = base_prev();
    assert_ok(&simple(&prev, txid, 0, &[])); // absent means ALL
    assert_ok(&simple(&prev, txid, 0, &[r_sighash(1)]));
    for bad in [0u32, 2, 3, 0x81, 0x82, 0x83, 0xffff_ffff] {
        let e = analyze_err(&simple(&prev, txid, 0, &[r_sighash(bad)]));
        assert_eq!(e.category, SemanticCategory::UnsupportedSighash, "{bad}");
    }
}

#[test]
fn signature_trailing_byte_must_be_all() {
    let (prev, txid) = base_prev();
    for bad in [0x02u8, 0x03, 0x81, 0x00] {
        let sig = der(&[0x01], &[0x01], bad);
        let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), &sig)]));
        assert_eq!(e.category, SemanticCategory::UnsupportedSighash, "{bad}");
    }
}

// ---------------------------------------------------------------
// Strict DER, low-S, pubkey syntax.
// ---------------------------------------------------------------

#[test]
fn strict_der_malformed_table() {
    let (prev, txid) = base_prev();
    let good = good_sig();
    let mutate = |i: usize, v: u8| {
        let mut s = good.clone();
        s[i] = v;
        s
    };
    let cases: Vec<Vec<u8>> = vec![
        vec![0x01; 8],                     // below minimum length
        vec![0x30; 74],                    // above maximum length
        mutate(0, 0x31),                   // wrong sequence tag
        mutate(1, 0x07),                   // wrong declared total length
        mutate(2, 0x03),                   // wrong R integer tag
        der(&[], &[0x01, 0x01], 0x01),     // zero-length R
        der(&[0x80], &[0x01], 0x01),       // negative R
        der(&[0x00, 0x01], &[0x01], 0x01), // padded non-negative R
        mutate(4 + 1, 0x03),               // wrong S integer tag
        der(&[0x01], &[], 0x01),           // zero-length S
        der(&[0x01], &[0x80], 0x01),       // negative S
        der(&[0x01], &[0x00, 0x7f], 0x01), // padded non-negative S
        good[..good.len() - 1].to_vec(),   // truncated by one byte
        vec![0xff; 40],                    // garbage
    ];
    for (n, sig) in cases.iter().enumerate() {
        let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), sig)]));
        assert_eq!(e.category, SemanticCategory::StrictDer, "case {n}");
    }
}

#[test]
fn der_padding_allowed_cases_pass() {
    let (prev, txid) = base_prev();
    // A zero pad byte is legal exactly when the next byte has its
    // high bit set.
    let sig = der(&[0x00, 0x80], &[0x00, 0xff], 0x01);
    assert_ok(&simple(&prev, txid, 0, &[r_sig(&pk(1), &sig)]));
}

#[test]
fn low_s_boundary() {
    let (prev, txid) = base_prev();
    let at_bound = der(&[0x01], &LOW_S_MAX, 0x01);
    assert_ok(&simple(&prev, txid, 0, &[r_sig(&pk(1), &at_bound)]));
    let mut over = LOW_S_MAX;
    over[31] = 0xa1;
    let sig = der(&[0x01], &over, 0x01);
    let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), &sig)]));
    assert_eq!(e.category, SemanticCategory::HighS);
    // 33-byte padded S above the bound is also high.
    let mut padded = vec![0x00, 0xff];
    padded.extend_from_slice(&[0xff; 31]);
    let sig = der(&[0x01], &padded, 0x01);
    let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), &sig)]));
    assert_eq!(e.category, SemanticCategory::HighS);
}

#[test]
fn pubkey_syntax_rejected() {
    let (prev, txid) = base_prev();
    let mut wrong_prefix = pk(1);
    wrong_prefix[0] = 0x04;
    let e = analyze_err(&simple(
        &prev,
        txid,
        0,
        &[r_sig(&wrong_prefix, &good_sig())],
    ));
    assert_eq!(e.category, SemanticCategory::CompressedPubkeySyntax);
    let uncompressed = [0x04; 65];
    let e = analyze_err(&simple(
        &prev,
        txid,
        0,
        &[r_sig(&uncompressed, &good_sig())],
    ));
    assert_eq!(e.category, SemanticCategory::CompressedPubkeySyntax);
}

// ---------------------------------------------------------------
// witnessScript form and structural candidate counting.
// ---------------------------------------------------------------

#[test]
fn multisig_candidate_counting_and_status() {
    let (prev, txid) = base_prev();
    let keys = [pk(1), pk(2), pk(3)];
    let ws = wscript(2, &keys);
    let check = |extra: &[Vec<u8>], expected_count: usize, expected: InputSignatureStatus| {
        let b = simple(&prev, txid, 0, extra);
        let view = parse(&b, InputSource::MicroSd).unwrap();
        let c = analyze_semantic_subset(&view).unwrap();
        assert_eq!(c.inputs[0].structural_signature_candidates, expected_count);
        assert_eq!(c.inputs[0].signature_status, expected);
        let form = c.inputs[0].multisig_form.unwrap();
        assert_eq!((form.required_m, form.total_n), (2, 3));
    };
    check(
        &[r_wscript(&ws)],
        0,
        InputSignatureStatus::BelowThresholdStructuralCandidate,
    );
    check(
        &[r_wscript(&ws), r_sig(&pk(1), &good_sig())],
        1,
        InputSignatureStatus::BelowThresholdStructuralCandidate,
    );
    check(
        &[
            r_wscript(&ws),
            r_sig(&pk(1), &good_sig()),
            r_sig(&pk(2), &good_sig()),
        ],
        2,
        InputSignatureStatus::ThresholdStructuralCandidateRequiresCryptographicVerification,
    );
    check(
        &[
            r_wscript(&ws),
            r_sig(&pk(1), &good_sig()),
            r_sig(&pk(2), &good_sig()),
            r_sig(&pk(3), &good_sig()),
        ],
        3,
        InputSignatureStatus::ThresholdStructuralCandidateRequiresCryptographicVerification,
    );
    // A structurally valid signature from a pubkey outside the
    // witnessScript never counts.
    check(
        &[
            r_wscript(&ws),
            r_sig(&pk(1), &good_sig()),
            r_sig(&pk(9), &good_sig()),
        ],
        1,
        InputSignatureStatus::BelowThresholdStructuralCandidate,
    );
}

#[test]
fn no_witness_script_means_no_structural_candidate() {
    let (prev, txid) = base_prev();
    let b = simple(&prev, txid, 0, &[r_sig(&pk(1), &good_sig())]);
    let view = parse(&b, InputSource::MicroSd).unwrap();
    let c = analyze_semantic_subset(&view).unwrap();
    assert_eq!(
        c.inputs[0].signature_status,
        InputSignatureStatus::WitnessScriptUnavailableNoStructuralCandidate
    );
    assert!(c.inputs[0].multisig_form.is_none());
    assert_eq!(c.inputs[0].structural_signature_candidates, 0);
    // Signatures are still validated without a witnessScript.
    let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), &[0xff; 40])]));
    assert_eq!(e.category, SemanticCategory::StrictDer);
}

#[test]
fn witness_script_form_table() {
    let (prev, txid) = base_prev();
    let k2 = [pk(1), pk(2)];
    let mut bad_key = wscript(1, &k2);
    bad_key[2] = 0x04; // first key byte not 02/03
    let mut no_cms = wscript(1, &k2);
    let last = no_cms.len() - 1;
    no_cms[last] = 0xac; // OP_CHECKSIG instead
    let mut wrong_n = wscript(1, &k2);
    let n_at = wrong_n.len() - 2;
    wrong_n[n_at] = 0x53; // OP_3 with two keys
    let mut trailing = wscript(1, &k2);
    trailing.push(0x00);
    let m_gt_n = wscript(2, &[pk(1)]);
    let sixteen: Vec<[u8; 33]> = (1..=16).map(pk).collect();
    let over_signers = wscript(16, &sixteen);
    for (n, ws) in [
        bad_key,
        no_cms,
        wrong_n,
        trailing,
        m_gt_n,
        over_signers,
        vec![],
        vec![0x51],
    ]
    .iter()
    .enumerate()
    {
        let e = analyze_err(&simple(&prev, txid, 0, &[r_wscript(ws)]));
        assert_eq!(e.category, SemanticCategory::WitnessScriptForm, "case {n}");
    }
    // 1-of-15 sits exactly at MAX_SIGNERS and is accepted.
    let fifteen: Vec<[u8; 33]> = (1..=15).map(pk).collect();
    assert_ok(&simple(&prev, txid, 0, &[r_wscript(&wscript(1, &fifteen))]));
}

#[test]
fn finalized_fields_surfaced_never_completion() {
    let (prev, txid) = base_prev();
    let keys = [pk(1), pk(2), pk(3)];
    let ws = wscript(2, &keys);
    for final_rec in [rec(&[0x07], &[0x51]), rec(&[0x08], &[0x01, 0x00])] {
        let b = simple(
            &prev,
            txid,
            0,
            &[
                r_wscript(&ws),
                r_sig(&pk(1), &good_sig()),
                r_sig(&pk(2), &good_sig()),
                final_rec.clone(),
            ],
        );
        let view = parse(&b, InputSource::MicroSd).unwrap();
        let c = analyze_semantic_subset(&view).unwrap();
        assert!(c.inputs[0].final_fields_require_cryptographic_verification);
        // Presence of final fields never upgrades or replaces the
        // structural status; verification stays deferred.
        assert_eq!(
            c.inputs[0].signature_status,
            InputSignatureStatus::ThresholdStructuralCandidateRequiresCryptographicVerification
        );
    }
}

// ---------------------------------------------------------------
// Script token iteration.
// ---------------------------------------------------------------

#[test]
fn script_token_iterator_and_malformed_push() {
    let script = [
        0x00, // OP_0 opcode token
        0x02, 0xaa, 0xbb, // direct push
        0x4c, 0x01, 0xcc, // PUSHDATA1
        0x4d, 0x02, 0x00, 0xdd, 0xee, // PUSHDATA2
        0x4e, 0x01, 0x00, 0x00, 0x00, 0xff, // PUSHDATA4
        0x51, 0xae, // opcodes
    ];
    let tokens: Vec<_> = ScriptTokens::new(&script).collect();
    let expected = [
        Ok(ScriptToken::Opcode(0x00)),
        Ok(ScriptToken::Push(&[0xaa, 0xbb][..])),
        Ok(ScriptToken::Push(&[0xcc][..])),
        Ok(ScriptToken::Push(&[0xdd, 0xee][..])),
        Ok(ScriptToken::Push(&[0xff][..])),
        Ok(ScriptToken::Opcode(0x51)),
        Ok(ScriptToken::Opcode(0xae)),
    ];
    assert_eq!(tokens.len(), expected.len());
    for (t, e) in tokens.iter().zip(expected.iter()) {
        assert_eq!(t, e);
    }
    // Overrunning pushes fail with the push opcode offset, then stop.
    let bad: Vec<_> = ScriptTokens::new(&[0x51, 0x4b]).collect();
    assert_eq!(bad.len(), 2);
    assert_eq!(bad[1].unwrap_err().offset, 1);
    let bad: Vec<_> = ScriptTokens::new(&[0x4d, 0x05, 0x00, 0xaa]).collect();
    assert_eq!(bad[0].unwrap_err().offset, 0);
}

#[test]
fn malformed_script_pushes_rejected_in_scripts() {
    // Unsigned output scriptPubKey with an overrunning push.
    let (prev, txid) = base_prev();
    let unsigned = unsigned_tx(&[(txid, 0)], &[(1, vec![0x02, 0xaa])]);
    let e = analyze_err(&psbt(&unsigned, &[vec![r_nwutxo(&prev)]], 1));
    assert_eq!(e.category, SemanticCategory::MalformedScriptPush);
    assert_eq!(e.input_index, None);
    // Selected prevout scriptPubKey with an overrunning push.
    let prev = prevtx_legacy(0x81, 1, &[], &[(100_000, vec![0x4c])]);
    let e = analyze_err(&simple(&prev, oracle_sha256d(&prev), 0, &[]));
    assert_eq!(e.category, SemanticCategory::MalformedScriptPush);
    assert_eq!(e.input_index, Some(0));
}

// ---------------------------------------------------------------
// Result facts, serializer neutrality, error display hygiene.
// ---------------------------------------------------------------

#[test]
fn analyzer_reports_facts_and_serializer_unchanged() {
    let (prev, txid) = base_prev();
    let b = simple(&prev, txid, 0, &[r_wutxo(100_000, &spk())]);
    let view = parse(&b, InputSource::MicroSd).unwrap();
    let before = canonical_serialize(&view).unwrap();
    let c = analyze_semantic_subset(&view).unwrap();
    assert_eq!(c.version, 2);
    assert_eq!(c.locktime, 0);
    assert_eq!(c.inputs[0].outpoint_txid_wire, txid.as_slice());
    assert_eq!(c.inputs[0].sequence, 0xffff_ffff);
    assert_eq!(c.inputs[0].prevout_amount, 100_000);
    assert_eq!(c.outputs.len(), 1);
    assert_eq!(c.outputs[0].amount, 90_000);
    assert_eq!(c.outputs[0].script_pubkey, spk().as_slice());
    assert_eq!(c.total_input_amount, 100_000);
    assert_eq!(c.total_output_amount, 90_000);
    assert_eq!(c.fee, 10_000);
    // Analysis never touches serialization or the buffer.
    let after = canonical_serialize(&view).unwrap();
    assert_eq!(before, after);
    assert_eq!(view.buffer(), b.as_slice());
}

#[test]
fn error_display_carries_no_attacker_bytes() {
    let (prev, _) = base_prev();
    let e = analyze_err(&simple(&prev, [0xab; 32], 0, &[]));
    let shown = format!("{e}");
    assert!(shown.contains("prevtx txid mismatch"));
    assert!(shown.contains("input 0"));
    assert!(!shown.contains("ab"), "{shown}");
}

// ---------------------------------------------------------------
// Frozen precedence.
// ---------------------------------------------------------------

#[test]
fn precedence_frozen_order() {
    let (prev, txid) = base_prev();
    // Inputs stage (ascending) precedes the signature stage: a bad
    // signature at input 0 loses to a missing prevtx at input 1.
    let prev_b = prevtx_legacy(0x91, 1, &[], &[(50_000, spk())]);
    let unsigned = unsigned_tx(&[(txid, 0), (oracle_sha256d(&prev_b), 0)], &[(1, spk())]);
    let b = psbt(
        &unsigned,
        &[vec![r_nwutxo(&prev), r_sig(&pk(1), &[0xff; 40])], vec![]],
        1,
    );
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::MissingPrevTx);
    assert_eq!(e.input_index, Some(1));
    // Ascending input order: input 0 vout error precedes input 1
    // missing prevtx.
    let unsigned = unsigned_tx(&[(txid, 9), (oracle_sha256d(&prev_b), 0)], &[(1, spk())]);
    let b = psbt(&unsigned, &[vec![r_nwutxo(&prev)], vec![]], 1);
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::VoutOutOfRange);
    assert_eq!(e.input_index, Some(0));
    // Totals/fee precede signature checks.
    let unsigned = unsigned_tx(&[(txid, 0)], &[(150_000, spk())]);
    let b = psbt(
        &unsigned,
        &[vec![r_nwutxo(&prev), r_sig(&pk(1), &[0xff; 40])]],
        1,
    );
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::NegativeFee);
    // Signature checks precede script token iteration.
    let unsigned = unsigned_tx(&[(txid, 0)], &[(1, vec![0x02, 0xaa])]);
    let b = psbt(
        &unsigned,
        &[vec![r_nwutxo(&prev), r_sig(&pk(1), &[0xff; 40])]],
        1,
    );
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::StrictDer);
}

// ---------------------------------------------------------------
// Determinism and no-panic under mutation and truncation.
// ---------------------------------------------------------------

#[test]
fn deterministic_no_panic_mutation_sweep() {
    let (prev, txid) = base_prev();
    let keys = [pk(1), pk(2), pk(3)];
    let base = simple(
        &prev,
        txid,
        0,
        &[
            r_wutxo(100_000, &spk()),
            r_sig(&pk(1), &good_sig()),
            r_sig(&pk(2), &good_sig()),
            r_wscript(&wscript(2, &keys)),
            r_sighash(1),
        ],
    );
    let run = |bytes: &[u8]| -> String {
        match parse(bytes, InputSource::MicroSd) {
            Ok(view) => format!("{:?}", analyze_semantic_subset(&view)),
            Err(e) => format!("parse:{e:?}"),
        }
    };
    for i in 0..base.len() {
        let mut m = base.clone();
        m[i] ^= 0xff;
        assert_eq!(run(&m), run(&m), "byte {i} not deterministic");
    }
    for len in 0..base.len() {
        let t = &base[..len];
        assert_eq!(run(t), run(t), "truncation {len} not deterministic");
    }
    assert!(run(&base).starts_with("Ok"));
}
