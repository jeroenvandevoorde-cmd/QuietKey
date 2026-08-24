//! M6 semantic-subset analyzer tests (QK-DEC-037/038/039). Locally
//! authored non-fundable fixtures only; no external vectors. The
//! test-local SHA-256 below is an independent oracle implementation,
//! cross-checked against hard-coded digests.

use qk_psbt::{
    analyze_and_verify_signatures, analyze_semantic_subset, canonical_serialize, parse,
    InputSignatureStatus, InputSource, ScriptToken, ScriptTokens, SemanticCategory, SemanticError,
    VerifiedAggregateStatus, VerifiedInputStatus,
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
fn zero_s_fails_closed_low_s_interval() {
    let (prev, txid) = base_prev();
    // QK-DEC-037 / BIP146: permitted S interval is 1..=HCO. Canonical
    // strict-DER S=0 (single 0x00 byte) must fail closed.
    let zero_s = der(&[0x01], &[0x00], 0x01);
    let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), &zero_s)]));
    assert_eq!(e.category, SemanticCategory::HighS);
    // S=1 is the smallest permitted value.
    let one_s = der(&[0x01], &[0x01], 0x01);
    assert_ok(&simple(&prev, txid, 0, &[r_sig(&pk(1), &one_s)]));
    // HCO itself is permitted.
    let at_bound = der(&[0x01], &LOW_S_MAX, 0x01);
    assert_ok(&simple(&prev, txid, 0, &[r_sig(&pk(1), &at_bound)]));
    // HCO+1 is rejected.
    let mut over = LOW_S_MAX;
    over[31] = 0xa1;
    let sig = der(&[0x01], &over, 0x01);
    let e = analyze_err(&simple(&prev, txid, 0, &[r_sig(&pk(1), &sig)]));
    assert_eq!(e.category, SemanticCategory::HighS);
}

#[test]
fn zero_s_candidates_cannot_reach_threshold_status() {
    let (prev, txid) = base_prev();
    let keys = [pk(1), pk(2), pk(3)];
    let ws = wscript(2, &keys);
    let zero_s = der(&[0x01], &[0x00], 0x01);
    // A 2-of-3 fixture whose candidate signatures carry S=0 must fail
    // closed at the first invalid signature rather than silently
    // omitting it, so threshold structural-candidate status is
    // unreachable.
    let b = simple(
        &prev,
        txid,
        0,
        &[
            r_wscript(&ws),
            r_sig(&pk(1), &zero_s),
            r_sig(&pk(2), &zero_s),
        ],
    );
    let e = analyze_err(&b);
    assert_eq!(e.category, SemanticCategory::HighS);
    // One good signature plus one zero-S signature also fails closed.
    let b = simple(
        &prev,
        txid,
        0,
        &[
            r_wscript(&ws),
            r_sig(&pk(1), &good_sig()),
            r_sig(&pk(2), &zero_s),
        ],
    );
    let e = analyze_err(&b);
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

// ===============================================================
// M8: read-only cryptographic verification of existing signatures
// (QK-DEC-044..046).
//
// The repository contains no signing capability. Everything below
// is a fixed, enumerated, public-only, non-fundable fixture table:
// compressed public keys, strict-DER signature values with a
// trailing SIGHASH_ALL byte, and expected outcomes against
// unsigned/public PSBT facts whose BIP143 digests are recomputed
// through the crate's KAT-anchored engine. The table values were
// generated outside the repository from high-entropy ephemeral keys
// using the vendored upstream libsecp256k1 with per-message RFC6979
// nonces; the generator, private material, and all intermediates
// were deleted before commit, and only public values are committed.
// No committed key is a documented or trivial multiple of G, and no
// committed signature uses a fixed or shared nonce across distinct
// key/digest pairs. Every table signature is cross-checked through
// the qk-secp verification boundary before the suite relies on it.
// ===============================================================

const M8_PK: [[u8; 33]; 15] = [
    [
        0x03, 0xf6, 0x06, 0xef, 0x9c, 0xbe, 0x9d, 0x07, 0x3b, 0x92, 0x97, 0x93, 0xae, 0xbf, 0x5b,
        0xd1, 0x66, 0xd0, 0x9b, 0x6a, 0xd1, 0x8d, 0x11, 0xa7, 0xa7, 0x0c, 0x3a, 0xa9, 0x69, 0x7d,
        0x41, 0x34, 0x5c,
    ],
    [
        0x03, 0x9b, 0x04, 0x4f, 0xde, 0x18, 0x2e, 0xdb, 0x62, 0x8d, 0x2d, 0xf6, 0x28, 0xbd, 0x35,
        0x44, 0xe9, 0x12, 0xee, 0x4e, 0x1a, 0x5f, 0xf2, 0xe3, 0x53, 0xc8, 0x96, 0x34, 0x90, 0x03,
        0xba, 0xa5, 0xb2,
    ],
    [
        0x02, 0xdc, 0x90, 0x8e, 0x0f, 0x82, 0xb0, 0x89, 0x7f, 0xcb, 0xbd, 0xc7, 0xd3, 0x40, 0x28,
        0x9b, 0x0f, 0x9e, 0xef, 0xc0, 0x11, 0xd3, 0xbf, 0x05, 0xbf, 0x03, 0x06, 0x1a, 0xb4, 0xd4,
        0xbd, 0x06, 0x96,
    ],
    [
        0x02, 0x87, 0x36, 0xfb, 0x98, 0x59, 0xe5, 0x0e, 0x2a, 0x0b, 0x6c, 0x3a, 0xe1, 0x67, 0x60,
        0x78, 0x05, 0x03, 0x0c, 0xb5, 0x44, 0x58, 0xc3, 0xc4, 0xf4, 0x2e, 0xff, 0x83, 0xd2, 0x68,
        0x37, 0x8f, 0xd2,
    ],
    [
        0x03, 0x58, 0xfa, 0xe1, 0xc4, 0x82, 0x80, 0xf6, 0x35, 0x85, 0x3f, 0x6c, 0x28, 0xb7, 0x95,
        0xb5, 0xb6, 0xf9, 0x63, 0xf0, 0xf0, 0x04, 0xd3, 0x5f, 0xb6, 0x4a, 0xeb, 0x42, 0xa4, 0xff,
        0x94, 0x9e, 0x09,
    ],
    [
        0x02, 0x37, 0xb0, 0x52, 0xb6, 0x09, 0xdb, 0xc7, 0x3b, 0x55, 0x07, 0x1f, 0xcf, 0x2c, 0x44,
        0xea, 0x26, 0x58, 0xfb, 0x02, 0xe9, 0xc4, 0x1e, 0xf4, 0x1b, 0xdb, 0x99, 0x53, 0xf7, 0x9a,
        0xc0, 0x69, 0xac,
    ],
    [
        0x02, 0x73, 0x38, 0x17, 0x5a, 0x9d, 0x8d, 0x64, 0xeb, 0x12, 0x0d, 0xe3, 0x78, 0xff, 0x0f,
        0xee, 0x3d, 0x4e, 0x1f, 0xd0, 0xd4, 0x80, 0x5d, 0x12, 0x0a, 0x9a, 0x11, 0x90, 0x92, 0x6a,
        0x9a, 0xb8, 0x58,
    ],
    [
        0x03, 0x95, 0x5c, 0x32, 0x90, 0xda, 0x7e, 0xef, 0x92, 0x12, 0x6f, 0x36, 0xef, 0xbc, 0x57,
        0xa6, 0xfd, 0x48, 0x47, 0x4d, 0xea, 0x15, 0x88, 0x65, 0x13, 0xa8, 0xc5, 0x9b, 0x8f, 0x48,
        0x73, 0xf0, 0x52,
    ],
    [
        0x02, 0x34, 0xe2, 0x78, 0x1a, 0x3a, 0x3a, 0x87, 0xc2, 0xfb, 0xa1, 0xfc, 0xc2, 0x03, 0xaa,
        0x8d, 0xc0, 0x80, 0x3e, 0x0b, 0xeb, 0x1f, 0x10, 0x7a, 0xa8, 0x4b, 0xd2, 0x58, 0x75, 0x0d,
        0x9b, 0xfd, 0x16,
    ],
    [
        0x03, 0xe0, 0x83, 0x24, 0xca, 0x8d, 0xb8, 0x6e, 0x5d, 0xa2, 0x0b, 0xe1, 0x71, 0x44, 0xdc,
        0x84, 0x06, 0x18, 0x35, 0x49, 0x15, 0xbe, 0x02, 0x34, 0x4b, 0x1a, 0xcc, 0xa0, 0x0d, 0x2c,
        0x15, 0x71, 0xab,
    ],
    [
        0x02, 0x9d, 0x54, 0x32, 0xf6, 0xbc, 0x13, 0x9a, 0x2a, 0x33, 0x2c, 0x4f, 0x0c, 0x48, 0x99,
        0xa1, 0x55, 0x96, 0x11, 0x54, 0xd2, 0x3e, 0xd9, 0xf0, 0x55, 0xc5, 0xeb, 0xdd, 0xc8, 0xfd,
        0xa0, 0xbf, 0x97,
    ],
    [
        0x03, 0x91, 0xd6, 0x7a, 0xc5, 0xc0, 0x50, 0xb0, 0x3f, 0x91, 0xbb, 0xf9, 0x84, 0xf3, 0x5b,
        0x04, 0x0c, 0x50, 0x0a, 0x52, 0xea, 0xd7, 0x63, 0x78, 0x1f, 0x47, 0xcd, 0xc1, 0x7b, 0xbf,
        0xe5, 0x1f, 0xdc,
    ],
    [
        0x03, 0x59, 0xe4, 0x6f, 0x57, 0xde, 0x49, 0x8a, 0xdd, 0x1f, 0xef, 0x70, 0xb3, 0x3d, 0xac,
        0xd9, 0xeb, 0xc6, 0xce, 0xbc, 0x43, 0xf2, 0xd3, 0x69, 0x3e, 0xb1, 0x87, 0x92, 0xc6, 0x2a,
        0xfc, 0xc9, 0x55,
    ],
    [
        0x02, 0xe6, 0xd1, 0x32, 0x93, 0x84, 0x2c, 0x7a, 0xd7, 0x87, 0x07, 0xa7, 0x9b, 0x3f, 0xd8,
        0xb4, 0x63, 0x6d, 0xb4, 0xd6, 0xd5, 0x04, 0xf1, 0x42, 0x78, 0x6e, 0xa6, 0x79, 0x7e, 0xd2,
        0xba, 0x84, 0x81,
    ],
    [
        0x02, 0xcb, 0xda, 0xee, 0x43, 0xb6, 0x0a, 0xb1, 0x87, 0x29, 0xdc, 0x78, 0x4d, 0x22, 0xc6,
        0x56, 0xbc, 0xa2, 0x27, 0x95, 0xfa, 0xa2, 0x18, 0x21, 0xeb, 0xc6, 0xff, 0x39, 0x05, 0xc9,
        0x66, 0x0a, 0xef,
    ],
];
const M8_OFFCURVE_PK: [u8; 33] = [
    0x02, 0xdd, 0xa1, 0x5c, 0xd5, 0x33, 0x24, 0x8a, 0x7c, 0xb3, 0xfc, 0x1b, 0x40, 0x02, 0xc2, 0x34,
    0x5b, 0x05, 0xca, 0x7f, 0x8f, 0x13, 0x43, 0xc3, 0x12, 0x8b, 0xf2, 0x70, 0x08, 0x44, 0x45, 0x90,
    0xd6,
];
const SIG_CROSS: [&[u8]; 4] = [
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xbb, 0xb9, 0xe9, 0xa7, 0x23, 0x49, 0xcd, 0xb9, 0xc6, 0x6b,
        0x3d, 0xd7, 0x06, 0x6a, 0x28, 0x9b, 0xc4, 0x68, 0x03, 0x0b, 0x15, 0xc4, 0xa9, 0x24, 0xad,
        0x3c, 0x76, 0x86, 0x76, 0x7b, 0x4a, 0xf8, 0x02, 0x20, 0x6e, 0x33, 0x9a, 0x3d, 0xc0, 0x58,
        0x5b, 0x27, 0x93, 0x54, 0x66, 0x8a, 0x85, 0xca, 0x7b, 0x9f, 0xd4, 0x52, 0x53, 0x5e, 0xe9,
        0xe3, 0x44, 0x7e, 0xb2, 0x79, 0x96, 0xe7, 0xe1, 0x78, 0xae, 0x61, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x6e, 0x2a, 0xb7, 0xf1, 0x0d, 0xc1, 0x1b, 0xff, 0x8e, 0x44, 0x68,
        0x6a, 0xb7, 0xf0, 0x11, 0x53, 0xb4, 0x5c, 0xcc, 0x99, 0xd5, 0x56, 0x09, 0xd4, 0x9c, 0x83,
        0xbf, 0xfc, 0x10, 0xe5, 0x1d, 0x1e, 0x02, 0x20, 0x1d, 0x0b, 0xde, 0x4b, 0xd6, 0x3c, 0xf6,
        0x20, 0xf7, 0x5e, 0xdd, 0x2b, 0x84, 0xe3, 0x12, 0xf2, 0xc0, 0x58, 0xc4, 0x7c, 0x0d, 0x28,
        0x7b, 0xfe, 0xa5, 0x52, 0xe8, 0xf2, 0xee, 0x85, 0x95, 0xa3, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xbb, 0xc9, 0xbd, 0xc1, 0x62, 0x7e, 0x8c, 0x84, 0xdb, 0x26,
        0xb1, 0xe9, 0x2b, 0x63, 0x16, 0x63, 0xd2, 0x3e, 0x33, 0xaf, 0x39, 0x25, 0xce, 0x29, 0x32,
        0x04, 0x3f, 0xf6, 0x5f, 0xc0, 0x9e, 0x33, 0x02, 0x20, 0x0b, 0x24, 0xca, 0x95, 0xaa, 0xd4,
        0x78, 0xf5, 0xa9, 0x36, 0x77, 0xf7, 0xc5, 0x37, 0xad, 0x91, 0xb6, 0xdc, 0xeb, 0xf9, 0x5b,
        0xc8, 0x09, 0x7d, 0x96, 0x75, 0x70, 0x57, 0xfe, 0x00, 0xff, 0x54, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x94, 0x85, 0x31, 0x60, 0x29, 0xaa, 0xdf, 0xf8, 0xdb, 0x78,
        0xf7, 0x76, 0xbc, 0xc0, 0xbc, 0x75, 0xfe, 0xcd, 0x01, 0x3e, 0x36, 0x4b, 0xda, 0x5d, 0xc4,
        0x41, 0x47, 0xf4, 0xcc, 0x40, 0x9e, 0x69, 0x02, 0x20, 0x6d, 0x78, 0x33, 0x70, 0xda, 0x8e,
        0x2c, 0xc2, 0x18, 0xb0, 0x3c, 0x3b, 0x46, 0x05, 0xca, 0xbf, 0xec, 0x60, 0xbd, 0xbf, 0x2e,
        0x64, 0xb9, 0x41, 0x9d, 0xbf, 0x37, 0xbf, 0xed, 0xf1, 0x16, 0xfd, 0x01,
    ],
];
const SIG_CROSS_HIGH: [&[u8]; 4] = [
    &[
        0x30, 0x46, 0x02, 0x21, 0x00, 0xbb, 0xb9, 0xe9, 0xa7, 0x23, 0x49, 0xcd, 0xb9, 0xc6, 0x6b,
        0x3d, 0xd7, 0x06, 0x6a, 0x28, 0x9b, 0xc4, 0x68, 0x03, 0x0b, 0x15, 0xc4, 0xa9, 0x24, 0xad,
        0x3c, 0x76, 0x86, 0x76, 0x7b, 0x4a, 0xf8, 0x02, 0x21, 0x00, 0x91, 0xcc, 0x65, 0xc2, 0x3f,
        0xa7, 0xa4, 0xd8, 0x6c, 0xab, 0x99, 0x75, 0x7a, 0x35, 0x84, 0x5e, 0xe6, 0x5c, 0x89, 0x87,
        0xc5, 0x65, 0x5b, 0xbd, 0x0d, 0x58, 0xc7, 0xa4, 0xee, 0xbd, 0x92, 0xe0, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x20, 0x6e, 0x2a, 0xb7, 0xf1, 0x0d, 0xc1, 0x1b, 0xff, 0x8e, 0x44, 0x68,
        0x6a, 0xb7, 0xf0, 0x11, 0x53, 0xb4, 0x5c, 0xcc, 0x99, 0xd5, 0x56, 0x09, 0xd4, 0x9c, 0x83,
        0xbf, 0xfc, 0x10, 0xe5, 0x1d, 0x1e, 0x02, 0x21, 0x00, 0xe2, 0xf4, 0x21, 0xb4, 0x29, 0xc3,
        0x09, 0xdf, 0x08, 0xa1, 0x22, 0xd4, 0x7b, 0x1c, 0xed, 0x0b, 0xfa, 0x56, 0x18, 0x6a, 0xa2,
        0x20, 0x24, 0x3d, 0x1a, 0x7f, 0x75, 0x99, 0xe1, 0xb0, 0xab, 0x9e, 0x01,
    ],
    &[
        0x30, 0x46, 0x02, 0x21, 0x00, 0xbb, 0xc9, 0xbd, 0xc1, 0x62, 0x7e, 0x8c, 0x84, 0xdb, 0x26,
        0xb1, 0xe9, 0x2b, 0x63, 0x16, 0x63, 0xd2, 0x3e, 0x33, 0xaf, 0x39, 0x25, 0xce, 0x29, 0x32,
        0x04, 0x3f, 0xf6, 0x5f, 0xc0, 0x9e, 0x33, 0x02, 0x21, 0x00, 0xf4, 0xdb, 0x35, 0x6a, 0x55,
        0x2b, 0x87, 0x0a, 0x56, 0xc9, 0x88, 0x08, 0x3a, 0xc8, 0x52, 0x6d, 0x03, 0xd1, 0xf0, 0xed,
        0x53, 0x80, 0x96, 0xbe, 0x29, 0x5c, 0xee, 0x34, 0xd2, 0x35, 0x41, 0xed, 0x01,
    ],
    &[
        0x30, 0x46, 0x02, 0x21, 0x00, 0x94, 0x85, 0x31, 0x60, 0x29, 0xaa, 0xdf, 0xf8, 0xdb, 0x78,
        0xf7, 0x76, 0xbc, 0xc0, 0xbc, 0x75, 0xfe, 0xcd, 0x01, 0x3e, 0x36, 0x4b, 0xda, 0x5d, 0xc4,
        0x41, 0x47, 0xf4, 0xcc, 0x40, 0x9e, 0x69, 0x02, 0x21, 0x00, 0x92, 0x87, 0xcc, 0x8f, 0x25,
        0x71, 0xd3, 0x3d, 0xe7, 0x4f, 0xc3, 0xc4, 0xb9, 0xfa, 0x35, 0x3e, 0xce, 0x4e, 0x1f, 0x27,
        0x80, 0xe3, 0xe6, 0xfa, 0x22, 0x13, 0x26, 0xcc, 0xe2, 0x45, 0x2a, 0x44, 0x01,
    ],
];
const SIG_THRESH: [&[u8]; 3] = [
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xb6, 0x55, 0xf3, 0x61, 0x8c, 0x33, 0x57, 0xe3, 0x3b, 0x62,
        0xa4, 0xe7, 0xe7, 0x84, 0x86, 0xf1, 0x0a, 0xb6, 0x72, 0x97, 0xc6, 0x85, 0xd6, 0xdb, 0x3c,
        0x2f, 0x3c, 0xe4, 0xad, 0x3a, 0x6c, 0xad, 0x02, 0x20, 0x2b, 0xc6, 0xf2, 0xbf, 0xcf, 0x2d,
        0xde, 0xcc, 0xca, 0xdb, 0xaf, 0xc7, 0x1b, 0x76, 0xbd, 0x3a, 0xb2, 0x51, 0xdc, 0x03, 0x5b,
        0xfb, 0xf0, 0x95, 0xcc, 0xaf, 0x45, 0x23, 0x4f, 0x47, 0x0b, 0xb6, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xa3, 0x50, 0xa9, 0x73, 0x67, 0xbf, 0x98, 0x46, 0xb2, 0x93,
        0x03, 0x14, 0x7a, 0xc9, 0xa0, 0x48, 0x53, 0xac, 0x59, 0x94, 0x44, 0x8c, 0x93, 0xb9, 0xe4,
        0x8c, 0xfa, 0xd9, 0xc7, 0x39, 0xdd, 0x75, 0x02, 0x20, 0x2a, 0x0e, 0x98, 0x9f, 0xbf, 0x88,
        0x1e, 0x04, 0x3b, 0xb1, 0x4e, 0xfc, 0x4f, 0xec, 0xab, 0xb4, 0xed, 0x27, 0x72, 0x03, 0x14,
        0xd6, 0x47, 0x16, 0x67, 0x2a, 0x36, 0x4d, 0x4b, 0x7a, 0x14, 0xe1, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x17, 0x59, 0x6d, 0xdd, 0x00, 0x29, 0x6b, 0xe0, 0x27, 0x6e, 0x79,
        0x92, 0x22, 0x6f, 0x1b, 0xbe, 0xc5, 0x91, 0xe3, 0x18, 0x04, 0x7f, 0x68, 0xfe, 0xcf, 0x88,
        0x55, 0xa8, 0x98, 0x61, 0x56, 0x87, 0x02, 0x20, 0x71, 0x1b, 0x23, 0x8b, 0x88, 0x36, 0x4a,
        0xde, 0x3a, 0x92, 0x6e, 0x5c, 0xdf, 0xa7, 0x77, 0x02, 0xdd, 0x6e, 0xda, 0x31, 0x10, 0x3b,
        0x63, 0x82, 0xc4, 0xa7, 0x3f, 0x2e, 0x05, 0x13, 0xc5, 0x7c, 0x01,
    ],
];
const SIG_AGG0: [&[u8]; 2] = [
    &[
        0x30, 0x43, 0x02, 0x1f, 0x12, 0x8e, 0x05, 0xd2, 0xdb, 0x18, 0xfa, 0xc3, 0x1e, 0xea, 0xf4,
        0xb8, 0x2d, 0x1f, 0x8e, 0xad, 0x47, 0xc2, 0x0c, 0xec, 0x82, 0x3d, 0x02, 0xf1, 0x90, 0xaf,
        0xc4, 0x2e, 0x9c, 0xd1, 0x21, 0x02, 0x20, 0x3a, 0xaa, 0xc9, 0x02, 0x30, 0x7e, 0x0a, 0xfe,
        0x6c, 0x8e, 0xad, 0x68, 0x2d, 0x45, 0xf4, 0x3a, 0x8f, 0xf1, 0xcd, 0xdf, 0x61, 0x88, 0xde,
        0x0e, 0x53, 0xf9, 0xff, 0x9e, 0x9c, 0x72, 0xdd, 0x9e, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xaf, 0x43, 0xa7, 0x3f, 0xb7, 0x74, 0x8e, 0x4c, 0xff, 0x2c,
        0xc3, 0x21, 0x1e, 0x8c, 0x0b, 0x51, 0x5e, 0xf7, 0xa2, 0x7c, 0xd8, 0xea, 0xf1, 0xec, 0x00,
        0xbc, 0x74, 0x68, 0xde, 0x16, 0xd1, 0xf5, 0x02, 0x20, 0x7c, 0xe2, 0x9d, 0x51, 0x50, 0x15,
        0xbb, 0xc0, 0xf9, 0x21, 0xe2, 0xcd, 0xa4, 0x10, 0x1e, 0x0e, 0xe2, 0xb7, 0x77, 0x42, 0x95,
        0x7b, 0x72, 0x8d, 0x33, 0x94, 0x17, 0xec, 0xe8, 0xfc, 0xd7, 0x99, 0x01,
    ],
];
const SIG_AGG1: [&[u8]; 2] = [
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xdf, 0x7d, 0x39, 0xa0, 0x9c, 0xb7, 0x58, 0x2a, 0x65, 0xfb,
        0xa6, 0xb8, 0x37, 0x24, 0x01, 0x87, 0x05, 0x29, 0x11, 0x12, 0x6a, 0xe9, 0x1d, 0x6b, 0x3a,
        0x57, 0x57, 0x57, 0x22, 0x0b, 0x0e, 0x61, 0x02, 0x20, 0x76, 0x01, 0xc3, 0x86, 0xc0, 0xaf,
        0x4d, 0xbb, 0x43, 0xc9, 0x5e, 0xf8, 0xf9, 0xe2, 0x0d, 0xe8, 0x78, 0x31, 0xd4, 0xd7, 0x1b,
        0xd0, 0x12, 0xbc, 0x4f, 0x6f, 0xe3, 0x7f, 0x97, 0xdf, 0xa6, 0x8d, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x7a, 0xa5, 0x33, 0xd0, 0x75, 0x29, 0xd0, 0xdd, 0x18, 0x02, 0x93,
        0x48, 0xc6, 0x66, 0xac, 0x84, 0xa4, 0xcb, 0x6e, 0x09, 0x04, 0x35, 0x45, 0xd4, 0x47, 0x10,
        0x43, 0x95, 0x8e, 0x09, 0x52, 0x16, 0x02, 0x20, 0x5f, 0x6a, 0xe8, 0xac, 0x13, 0x6b, 0x21,
        0x12, 0x53, 0x2e, 0x4b, 0xb8, 0xf9, 0xe8, 0x57, 0xf8, 0x31, 0xdb, 0xc3, 0x03, 0x12, 0xdc,
        0xa0, 0xef, 0x09, 0x49, 0x7a, 0xb4, 0xe0, 0xab, 0xdd, 0x69, 0x01,
    ],
];
const SIG_FINAL: [&[u8]; 2] = [
    &[
        0x30, 0x44, 0x02, 0x20, 0x16, 0x67, 0x67, 0x66, 0x8f, 0x05, 0x33, 0x00, 0x51, 0x58, 0x78,
        0x41, 0x17, 0xf5, 0x43, 0x54, 0x06, 0x39, 0x72, 0x01, 0xc6, 0xf2, 0xf3, 0xaf, 0x24, 0x58,
        0x74, 0xca, 0x2d, 0x3b, 0x6d, 0x16, 0x02, 0x20, 0x2a, 0x43, 0xa1, 0xd9, 0xd2, 0xa1, 0x5a,
        0xd0, 0x07, 0xd3, 0x47, 0xbf, 0xf7, 0xe0, 0xbc, 0xb5, 0x1b, 0xdf, 0xa8, 0xfe, 0xb0, 0xe5,
        0x3f, 0x06, 0x32, 0x04, 0x5c, 0xa5, 0xdc, 0x6a, 0x3c, 0x48, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x52, 0xaf, 0x92, 0x22, 0x55, 0xa8, 0xdb, 0x73, 0x65, 0x05, 0x44,
        0x5d, 0x99, 0x14, 0x62, 0x3c, 0x5f, 0x9e, 0xab, 0x4d, 0xe5, 0x73, 0x32, 0x7c, 0xf5, 0x80,
        0x70, 0x05, 0x41, 0x3d, 0xd4, 0x39, 0x02, 0x20, 0x50, 0x1f, 0x45, 0xa5, 0xf3, 0xeb, 0x89,
        0xee, 0x1e, 0xeb, 0x52, 0x39, 0xb8, 0x7b, 0x8c, 0xda, 0xef, 0x4c, 0xcd, 0xc5, 0x1d, 0x22,
        0x41, 0x60, 0xcc, 0xe6, 0x8a, 0x71, 0x83, 0xc7, 0xd4, 0x10, 0x01,
    ],
];
const SIG_FAKEMEM: [&[u8]; 2] = [
    &[
        0x30, 0x44, 0x02, 0x20, 0x1f, 0xfd, 0xa0, 0x28, 0xb1, 0x67, 0x1f, 0x5f, 0x0c, 0xf0, 0x29,
        0xb7, 0x23, 0x80, 0x29, 0x5a, 0xb9, 0x93, 0xec, 0x0d, 0xb2, 0x42, 0x54, 0xa6, 0x48, 0xe3,
        0x02, 0xe3, 0x46, 0x3c, 0xd2, 0x51, 0x02, 0x20, 0x1a, 0x5c, 0x9c, 0x8a, 0xce, 0x64, 0x75,
        0xa1, 0xb8, 0x28, 0xc4, 0x42, 0x57, 0xe1, 0xd7, 0x12, 0xc2, 0x0b, 0x60, 0x46, 0x18, 0xf5,
        0xe6, 0xf1, 0x8e, 0x6c, 0xea, 0xfa, 0xe3, 0x3d, 0x76, 0x39, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x6f, 0x9b, 0x87, 0x61, 0x1a, 0x9c, 0x7a, 0xab, 0xbd, 0xd5, 0x2d,
        0x99, 0x73, 0xfa, 0x7f, 0xda, 0x3f, 0x3d, 0x0a, 0xca, 0x44, 0x7f, 0xda, 0xae, 0x09, 0xff,
        0xa2, 0x5d, 0xa4, 0xe8, 0x3a, 0xfb, 0x02, 0x20, 0x77, 0x58, 0x7e, 0x8d, 0xe9, 0xc6, 0x4c,
        0xd7, 0xe3, 0x4b, 0x72, 0xe4, 0xcc, 0xd9, 0xb3, 0xd2, 0x36, 0x1b, 0xb0, 0xdb, 0x1e, 0x89,
        0x23, 0x1d, 0x02, 0xeb, 0xcd, 0xf3, 0x2b, 0x49, 0x92, 0xbb, 0x01,
    ],
];
const SIG_MEMB: [&[u8]; 2] = [
    &[
        0x30, 0x44, 0x02, 0x20, 0x7e, 0x50, 0x0d, 0x7d, 0xcd, 0x37, 0xf1, 0x7c, 0x2b, 0x8a, 0x41,
        0x40, 0x06, 0xb7, 0x91, 0x24, 0x81, 0x0f, 0xf9, 0x78, 0xea, 0x53, 0x71, 0x5d, 0x80, 0x0b,
        0x41, 0x9d, 0xd8, 0xd7, 0x7c, 0x68, 0x02, 0x20, 0x65, 0x0e, 0x41, 0x09, 0x72, 0xd6, 0x50,
        0xd2, 0xb6, 0x8d, 0x2d, 0x6b, 0x71, 0xec, 0x67, 0x4f, 0x97, 0x89, 0x92, 0x54, 0x88, 0x70,
        0x9d, 0xc1, 0x85, 0x99, 0x92, 0xd2, 0xb4, 0xdb, 0x87, 0xfd, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x86, 0xa8, 0x66, 0xf0, 0xf5, 0x22, 0x55, 0x1e, 0x21, 0x32,
        0xe5, 0xdd, 0xf7, 0x65, 0x3b, 0xe6, 0xa6, 0xe8, 0x65, 0x0a, 0x8c, 0x0e, 0x0a, 0xdc, 0x48,
        0x38, 0x20, 0xa3, 0x82, 0x8f, 0x1c, 0x36, 0x02, 0x20, 0x3b, 0x5a, 0x18, 0x20, 0x82, 0x5b,
        0xa7, 0xa0, 0x87, 0x52, 0x65, 0x00, 0xbf, 0x27, 0x4b, 0xe9, 0x06, 0x71, 0x5c, 0xc3, 0x1c,
        0x46, 0xef, 0xec, 0x93, 0x43, 0xdc, 0x43, 0x77, 0x31, 0x54, 0xdb, 0x01,
    ],
];
const SIG_MEMB_NONMEMBER: &[u8] = &[
    0x30, 0x44, 0x02, 0x20, 0x33, 0x1e, 0xad, 0x64, 0x36, 0xa5, 0x64, 0x49, 0xd9, 0x9d, 0x5e, 0x6b,
    0x96, 0xf1, 0x81, 0x22, 0x92, 0x48, 0x97, 0x23, 0x3a, 0x3d, 0xed, 0xbe, 0x1e, 0x71, 0xdd, 0xe9,
    0x59, 0x50, 0xbb, 0x83, 0x02, 0x20, 0x0a, 0x96, 0x38, 0x1a, 0x1c, 0x4a, 0x4a, 0x60, 0xf2, 0xe8,
    0x26, 0xe3, 0x77, 0x7f, 0x20, 0xf5, 0xd5, 0x02, 0xcc, 0x3b, 0x09, 0xff, 0xdb, 0x99, 0xcb, 0x02,
    0xb8, 0xe4, 0x2a, 0x0a, 0x77, 0x00, 0x01,
];
const SIG_MEMB_HIGH: &[u8] = &[
    0x30, 0x45, 0x02, 0x20, 0x7e, 0x50, 0x0d, 0x7d, 0xcd, 0x37, 0xf1, 0x7c, 0x2b, 0x8a, 0x41, 0x40,
    0x06, 0xb7, 0x91, 0x24, 0x81, 0x0f, 0xf9, 0x78, 0xea, 0x53, 0x71, 0x5d, 0x80, 0x0b, 0x41, 0x9d,
    0xd8, 0xd7, 0x7c, 0x68, 0x02, 0x21, 0x00, 0x9a, 0xf1, 0xbe, 0xf6, 0x8d, 0x29, 0xaf, 0x2d, 0x49,
    0x72, 0xd2, 0x94, 0x8e, 0x13, 0x98, 0xaf, 0x23, 0x25, 0x4a, 0x92, 0x26, 0xd8, 0x02, 0x7a, 0x3a,
    0x38, 0xcb, 0xba, 0x1b, 0x5a, 0xb9, 0x44, 0x01,
];
const SIG_OFFCURVE_WS: &[u8] = &[
    0x30, 0x44, 0x02, 0x20, 0x27, 0xf6, 0x41, 0x2c, 0xb4, 0xbe, 0x09, 0x2c, 0x28, 0xb1, 0x3d, 0xa6,
    0xa5, 0x42, 0xdc, 0x7d, 0x47, 0x94, 0x67, 0x7e, 0xba, 0x59, 0x54, 0x1f, 0x23, 0x7b, 0xe5, 0xb9,
    0x5c, 0x1f, 0xfa, 0x44, 0x02, 0x20, 0x67, 0x6e, 0xbe, 0x35, 0x80, 0x94, 0xc4, 0xed, 0x77, 0x86,
    0x62, 0x62, 0x00, 0x22, 0x3f, 0xa2, 0xee, 0xf4, 0x96, 0x3f, 0xd9, 0xbf, 0xcd, 0x05, 0x2c, 0x74,
    0x61, 0xc5, 0x76, 0x21, 0xd9, 0xac, 0x01,
];
const SIG_FIFTEEN: [&[u8]; 15] = [
    &[
        0x30, 0x44, 0x02, 0x20, 0x0e, 0xa2, 0x84, 0xa6, 0xeb, 0xa1, 0x49, 0xb4, 0x0d, 0x3e, 0xee,
        0xaf, 0x05, 0xb2, 0xd5, 0x22, 0x50, 0x70, 0xda, 0xc6, 0x20, 0x25, 0x4b, 0xd7, 0x83, 0x8e,
        0x75, 0xc7, 0xff, 0xbc, 0x2e, 0x07, 0x02, 0x20, 0x1a, 0xbf, 0xb7, 0x5d, 0x8e, 0xfb, 0xa9,
        0x2b, 0x11, 0x49, 0x2d, 0xd3, 0x19, 0xc9, 0xbe, 0xaf, 0x41, 0x0a, 0x95, 0x82, 0x60, 0x4c,
        0xf0, 0xe2, 0xaa, 0x78, 0x9a, 0x4b, 0x30, 0x33, 0xce, 0xea, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xff, 0xe9, 0xf1, 0xcc, 0x0a, 0xcd, 0x5c, 0x5e, 0xb5, 0x23,
        0x52, 0x63, 0x24, 0x0e, 0x43, 0x0b, 0xe4, 0x94, 0x7e, 0xf9, 0xeb, 0x1f, 0x8d, 0x72, 0x3e,
        0x66, 0xe9, 0x3d, 0xfb, 0x52, 0xce, 0x50, 0x02, 0x20, 0x0c, 0x67, 0x85, 0xa3, 0x1f, 0x10,
        0x74, 0xbf, 0xc9, 0x60, 0x0a, 0x03, 0xa6, 0x85, 0xec, 0x5f, 0x45, 0x21, 0x50, 0x89, 0x29,
        0xb2, 0x62, 0x1e, 0xfd, 0x1d, 0x9c, 0xdc, 0x2f, 0xd8, 0x31, 0x0d, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xe5, 0x8c, 0xae, 0x06, 0x5a, 0x62, 0x87, 0x9c, 0x20, 0x13,
        0x9a, 0x22, 0xe4, 0x90, 0x01, 0x63, 0xa5, 0x61, 0xef, 0x52, 0x6d, 0x49, 0x94, 0xc5, 0xaa,
        0x4f, 0x1e, 0x0b, 0x98, 0x55, 0xfb, 0x0e, 0x02, 0x20, 0x47, 0x50, 0x31, 0xbb, 0xc7, 0x0f,
        0x38, 0xce, 0x95, 0x0a, 0xe5, 0xc6, 0x49, 0x8f, 0x22, 0xb5, 0x7c, 0x3c, 0x43, 0x6e, 0x15,
        0xad, 0xe2, 0x37, 0x91, 0x4a, 0xcc, 0x76, 0x61, 0x12, 0x1b, 0xc3, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x7a, 0xae, 0xc6, 0xd7, 0xef, 0x82, 0xeb, 0x46, 0x9e, 0x32, 0x31,
        0xfd, 0xf1, 0xf9, 0x58, 0x25, 0x75, 0x57, 0xc8, 0x24, 0xc8, 0x30, 0x08, 0x5a, 0xbe, 0xad,
        0x57, 0x05, 0xef, 0x0e, 0xdc, 0x49, 0x02, 0x20, 0x14, 0xa1, 0x98, 0xa4, 0x7e, 0x2f, 0x32,
        0xea, 0x3a, 0x34, 0x35, 0x6e, 0xfc, 0x66, 0x2f, 0x7f, 0xfd, 0x38, 0x6e, 0x9c, 0x69, 0xe4,
        0xe6, 0x9e, 0xca, 0xf7, 0x97, 0x6e, 0xf2, 0xe3, 0xfe, 0x4c, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x85, 0x28, 0xd8, 0xda, 0x05, 0xdd, 0x95, 0x5c, 0x72, 0x04,
        0x22, 0x8b, 0x22, 0xa9, 0x9a, 0x62, 0x5c, 0x14, 0x8d, 0xee, 0x27, 0xdc, 0xa3, 0x0e, 0xfb,
        0xa2, 0xf9, 0xe4, 0xf4, 0x50, 0xb9, 0x09, 0x02, 0x20, 0x2d, 0x2e, 0x2f, 0x62, 0xbb, 0xb0,
        0x66, 0x68, 0x28, 0x96, 0x3a, 0x67, 0x21, 0x12, 0xeb, 0x48, 0x53, 0xd0, 0x48, 0xa7, 0x25,
        0xdb, 0x4e, 0x0a, 0x67, 0xeb, 0x43, 0x7e, 0xb9, 0x3c, 0x4a, 0x69, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x42, 0x9f, 0x51, 0x64, 0x97, 0x63, 0x8c, 0x5d, 0x30, 0x3f, 0xe8,
        0x7b, 0x9c, 0x0f, 0x0a, 0xb0, 0xc9, 0xac, 0x90, 0x85, 0xcb, 0x88, 0x19, 0x84, 0x99, 0xdb,
        0xd7, 0x3a, 0xb0, 0x22, 0xc6, 0xe4, 0x02, 0x20, 0x29, 0x9a, 0xe8, 0x18, 0x50, 0x04, 0x2d,
        0xcf, 0x01, 0xc2, 0x23, 0xf9, 0x1b, 0x56, 0x7a, 0xf9, 0x4a, 0x2a, 0xac, 0x0b, 0x17, 0x83,
        0x5f, 0xa6, 0x63, 0x21, 0xbb, 0x95, 0x24, 0x32, 0x1b, 0xca, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xcf, 0xd1, 0x5e, 0x5a, 0x60, 0x5d, 0x37, 0x14, 0x54, 0x95,
        0xbb, 0x9f, 0x04, 0x17, 0x6b, 0xea, 0xcd, 0xa0, 0xa7, 0xf2, 0x7f, 0xfa, 0xff, 0xb0, 0xf0,
        0x86, 0x0a, 0x4a, 0x22, 0x91, 0xf3, 0x2e, 0x02, 0x20, 0x1c, 0x74, 0x94, 0xe9, 0xc2, 0x93,
        0xd7, 0x51, 0x7e, 0x3f, 0x8e, 0x2d, 0x51, 0xea, 0x6f, 0xca, 0x54, 0x09, 0x06, 0x55, 0xec,
        0x68, 0xe5, 0x57, 0x21, 0x1e, 0x73, 0x21, 0x1f, 0x5b, 0x12, 0x6b, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x7f, 0xc8, 0x17, 0xbb, 0x1d, 0xe3, 0xe3, 0x90, 0xe5, 0xaa, 0x5a,
        0xc5, 0x5b, 0xc4, 0x71, 0x30, 0x11, 0xe3, 0xa4, 0x31, 0x01, 0x7e, 0x90, 0x22, 0xc4, 0xe2,
        0x24, 0x7f, 0x53, 0x46, 0xba, 0x0e, 0x02, 0x20, 0x55, 0xdf, 0x15, 0xc4, 0xc4, 0xea, 0x10,
        0x70, 0x5d, 0x84, 0xc1, 0x10, 0x9b, 0x93, 0xad, 0x79, 0xcd, 0x59, 0x87, 0x39, 0x24, 0x6a,
        0x21, 0x37, 0x0f, 0xa4, 0x3d, 0x04, 0x74, 0x82, 0x0b, 0x4c, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x44, 0x03, 0xf5, 0x21, 0x03, 0x55, 0x95, 0x45, 0xff, 0xe3, 0xaf,
        0xcf, 0x6d, 0x67, 0x7a, 0x9c, 0xcf, 0x38, 0xc7, 0xf3, 0x0d, 0x79, 0xdd, 0x01, 0x2d, 0x9e,
        0x45, 0xb1, 0x40, 0xd0, 0x9e, 0x14, 0x02, 0x20, 0x35, 0x32, 0x66, 0xcd, 0xcb, 0xec, 0x5c,
        0x35, 0x4e, 0xe1, 0x5b, 0xc1, 0xc9, 0xfc, 0x9c, 0xba, 0xaf, 0xa3, 0x66, 0xf7, 0xc9, 0x31,
        0xe6, 0xb7, 0x51, 0x9c, 0xec, 0x0e, 0x39, 0x81, 0xec, 0xcd, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xab, 0x74, 0x53, 0xec, 0xfb, 0xc3, 0x8d, 0x4c, 0xe5, 0xd1,
        0x93, 0x4a, 0x1e, 0xa4, 0xd0, 0x08, 0xdc, 0x9b, 0x76, 0xf9, 0x4e, 0x4c, 0xd9, 0x03, 0xfb,
        0xa0, 0xc4, 0xfe, 0x0a, 0x3f, 0xde, 0x23, 0x02, 0x20, 0x53, 0xab, 0x0b, 0x33, 0x7f, 0xf9,
        0x08, 0x83, 0xba, 0x6c, 0x59, 0x0c, 0xcd, 0x33, 0x39, 0x34, 0xc7, 0x7a, 0x01, 0x17, 0x8c,
        0x04, 0xd0, 0xf0, 0x79, 0xb9, 0xb1, 0x97, 0x85, 0x94, 0x70, 0xbc, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x8f, 0x09, 0x58, 0xa4, 0x5b, 0xa4, 0x49, 0xb8, 0x39, 0x57,
        0xc2, 0x8f, 0xf1, 0x00, 0x09, 0x38, 0xff, 0x1d, 0x59, 0x0b, 0xe1, 0x6b, 0x9d, 0x37, 0xe9,
        0x31, 0xfc, 0x10, 0xae, 0x1a, 0x5f, 0x15, 0x02, 0x20, 0x1c, 0xa4, 0xcf, 0x5b, 0xe6, 0xb5,
        0x26, 0xb3, 0x10, 0xe6, 0xab, 0xa2, 0x42, 0xea, 0x4f, 0x2c, 0xb0, 0xc1, 0xca, 0xa3, 0xfc,
        0x39, 0x5a, 0x51, 0x7a, 0xb0, 0xf8, 0xc1, 0xc7, 0x05, 0xb0, 0x93, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x81, 0x6d, 0x1e, 0xb9, 0x5a, 0x43, 0xd8, 0x7b, 0xb5, 0xa2,
        0xab, 0xb5, 0x01, 0x38, 0x94, 0x92, 0xc3, 0xd4, 0xb3, 0x0a, 0x43, 0xd0, 0x5a, 0x68, 0xd2,
        0x87, 0xc0, 0xae, 0x49, 0xf9, 0x50, 0x9a, 0x02, 0x20, 0x6c, 0x29, 0x25, 0x8c, 0xcc, 0xe8,
        0x61, 0x32, 0x5d, 0x50, 0xaa, 0x49, 0xf8, 0xc6, 0xc7, 0x7c, 0xaa, 0x19, 0xef, 0x08, 0xe2,
        0x8d, 0x38, 0x54, 0xaf, 0xa7, 0x6b, 0x75, 0x47, 0x85, 0xf5, 0x37, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x62, 0x44, 0x04, 0x13, 0x71, 0x6f, 0x4e, 0x1e, 0xaf, 0xd8, 0x60,
        0x9e, 0xce, 0xa3, 0xdb, 0xad, 0xb4, 0x6c, 0xaf, 0x27, 0xc9, 0x19, 0x3c, 0x67, 0xfa, 0x8e,
        0xa9, 0xcb, 0xc1, 0xab, 0x71, 0x27, 0x02, 0x20, 0x55, 0x10, 0xca, 0xae, 0xf8, 0x92, 0x55,
        0xe3, 0xf5, 0x9a, 0xee, 0x49, 0xba, 0x61, 0xbc, 0x2d, 0xce, 0x57, 0x9f, 0x6d, 0x47, 0xf3,
        0xdb, 0xc8, 0x33, 0xf8, 0x7a, 0x41, 0x7f, 0x2d, 0x9b, 0x2a, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xfd, 0xd5, 0x17, 0x6b, 0xb9, 0x0e, 0x65, 0xc6, 0xb3, 0xd1,
        0x47, 0x00, 0x83, 0x62, 0x2f, 0x82, 0x50, 0x0d, 0x07, 0xd2, 0x1d, 0x35, 0xe1, 0x90, 0xd6,
        0xc5, 0xb6, 0xcb, 0xca, 0xc1, 0x45, 0xb4, 0x02, 0x20, 0x22, 0x70, 0xea, 0xb1, 0x05, 0xfe,
        0x9f, 0xfd, 0x3b, 0x16, 0xfa, 0xd5, 0x1f, 0x82, 0x7e, 0x35, 0xa5, 0x86, 0x1c, 0x40, 0xcc,
        0xa5, 0x45, 0x13, 0xb2, 0x39, 0x59, 0x89, 0x96, 0x55, 0xdf, 0xd5, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x6f, 0x1e, 0x7a, 0x85, 0x02, 0xe7, 0x38, 0xef, 0x1c, 0x73, 0x3b,
        0x1f, 0x08, 0x38, 0x20, 0x70, 0x56, 0xf1, 0xc5, 0x7f, 0xe4, 0x2c, 0x5f, 0x96, 0x27, 0x35,
        0xbf, 0x09, 0xdc, 0xf2, 0x66, 0x37, 0x02, 0x20, 0x4a, 0xf1, 0x88, 0xf4, 0xde, 0x01, 0x7d,
        0xcc, 0x5e, 0x18, 0x3d, 0x97, 0xe5, 0x30, 0x1c, 0x04, 0x66, 0x59, 0x76, 0x33, 0xba, 0xde,
        0x4c, 0x4f, 0xd5, 0xe9, 0xa9, 0xb4, 0x2c, 0xed, 0x76, 0xe3, 0x01,
    ],
];
const SIG_SENS0: [&[u8]; 2] = [
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x8d, 0x97, 0x59, 0xa3, 0xd2, 0x4d, 0xa8, 0xc6, 0xb1, 0x08,
        0x09, 0xee, 0x2b, 0xde, 0xf7, 0x05, 0x59, 0x75, 0x8d, 0xcc, 0x5c, 0x55, 0x02, 0x91, 0x8d,
        0x0c, 0x71, 0xfc, 0xa7, 0xe9, 0xce, 0xa0, 0x02, 0x20, 0x1f, 0x4c, 0x94, 0x3e, 0x76, 0xe7,
        0x2f, 0x40, 0xb6, 0x41, 0x6e, 0xd0, 0x96, 0x89, 0x4f, 0x08, 0xb9, 0x62, 0x95, 0x05, 0x54,
        0x4b, 0x21, 0x5a, 0x24, 0xfb, 0x22, 0x57, 0x7a, 0x95, 0x71, 0xdf, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x99, 0x68, 0x5a, 0xd1, 0x01, 0x65, 0x11, 0x22, 0x92, 0x76,
        0x49, 0x5d, 0x10, 0x69, 0x27, 0x40, 0xc9, 0x3f, 0x21, 0x2e, 0x27, 0xa5, 0x81, 0x32, 0x9b,
        0x78, 0xc0, 0xb8, 0xa6, 0x4c, 0xd4, 0x7c, 0x02, 0x20, 0x61, 0x4f, 0x4a, 0x2e, 0xee, 0xfa,
        0xa9, 0xe7, 0x97, 0xa5, 0xe0, 0x8a, 0x6e, 0x3a, 0x05, 0x41, 0xc5, 0x93, 0x7b, 0x00, 0x4b,
        0x4f, 0x1f, 0x40, 0xd3, 0x84, 0xe1, 0x32, 0x8e, 0xf1, 0xb0, 0xdd, 0x01,
    ],
];
const SIG_SENS1: [&[u8]; 2] = [
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x9b, 0x03, 0xab, 0x5e, 0x43, 0x86, 0xf6, 0x0c, 0xd3, 0xa3,
        0x43, 0xef, 0x95, 0xdd, 0x80, 0xaa, 0x05, 0x16, 0x98, 0xcd, 0xa2, 0x75, 0xfe, 0x5a, 0xe8,
        0x8d, 0x50, 0xc1, 0xa5, 0x3c, 0xcd, 0xcf, 0x02, 0x20, 0x60, 0xbc, 0x46, 0xdb, 0xa6, 0x07,
        0x22, 0x1a, 0x76, 0x13, 0x89, 0xff, 0xbe, 0xdf, 0x93, 0xe0, 0x44, 0xd9, 0x00, 0x0d, 0xb3,
        0x82, 0x87, 0x61, 0xba, 0x36, 0xcf, 0xcb, 0xa9, 0x09, 0x8f, 0x9a, 0x01,
    ],
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0x9f, 0x97, 0xec, 0x76, 0x8d, 0x10, 0x86, 0xd1, 0xc3, 0x8d,
        0xeb, 0x11, 0x24, 0xae, 0xa7, 0x90, 0xf3, 0x45, 0x64, 0x3e, 0x2b, 0x44, 0xed, 0xe3, 0x7f,
        0x20, 0x26, 0x46, 0xaf, 0xf0, 0x39, 0xc1, 0x02, 0x20, 0x06, 0x4d, 0x5c, 0x22, 0x43, 0xff,
        0xea, 0x26, 0x55, 0xc2, 0xa8, 0x59, 0xab, 0x11, 0x1d, 0xd0, 0x1d, 0x4b, 0x37, 0xa4, 0xd6,
        0x7f, 0x3d, 0x3e, 0x29, 0x6b, 0xb8, 0xde, 0xea, 0x6e, 0x50, 0x6b, 0x01,
    ],
];
const SIG_DET: [&[u8]; 2] = [
    &[
        0x30, 0x45, 0x02, 0x21, 0x00, 0xeb, 0x24, 0x1c, 0xac, 0x98, 0x59, 0xc6, 0xf1, 0x2a, 0x40,
        0x7f, 0xfe, 0x09, 0x20, 0x1e, 0xc4, 0xea, 0x59, 0x56, 0xde, 0xcb, 0xe9, 0x34, 0x1e, 0xe5,
        0x6f, 0x38, 0xf6, 0x8f, 0x0f, 0xc7, 0x66, 0x02, 0x20, 0x4a, 0x8f, 0x25, 0x6d, 0x9f, 0x8d,
        0x77, 0x36, 0x51, 0x97, 0x38, 0x28, 0x7f, 0xc3, 0xbc, 0x07, 0x33, 0xbc, 0x10, 0x3f, 0x54,
        0xbc, 0x02, 0x18, 0x1a, 0xdd, 0x70, 0xb2, 0x33, 0x8b, 0x63, 0x9e, 0x01,
    ],
    &[
        0x30, 0x44, 0x02, 0x20, 0x52, 0x8c, 0x75, 0x7a, 0xa9, 0x25, 0xbb, 0x73, 0xa9, 0x44, 0x3a,
        0xd4, 0x3e, 0xfa, 0x58, 0xf1, 0x56, 0x7d, 0x23, 0xd0, 0xb6, 0x3d, 0x63, 0xae, 0xd1, 0x31,
        0xa9, 0xfc, 0x8e, 0x92, 0x4c, 0x7c, 0x02, 0x20, 0x73, 0xb8, 0xb9, 0xfe, 0x08, 0x2f, 0x17,
        0xbe, 0x29, 0xdc, 0x7a, 0x5f, 0xe2, 0xc8, 0x45, 0x65, 0x95, 0xfd, 0x6a, 0xd3, 0x47, 0x80,
        0xce, 0x99, 0xf4, 0x93, 0x6e, 0xe4, 0xaf, 0xbb, 0x28, 0xdf, 0x01,
    ],
];

/// Fixed public member key `i` of the fixture table.
fn fx_pk(i: usize) -> [u8; 33] {
    M8_PK[i]
}

// ---------------------------------------------------------------
// M8 fixture builders.
// ---------------------------------------------------------------

fn p2wsh(ws: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0x20];
    v.extend_from_slice(&oracle_sha256(ws));
    v
}

/// M8 input spec: witnessScript, prevout amount, prevtx salt, and
/// extra input-map records appended after non_witness_utxo (and the
/// witnessScript record unless omitted).
#[derive(Clone)]
struct M8In {
    ws: Vec<u8>,
    amount: u64,
    salt: u8,
    records: Vec<Vec<u8>>,
    omit_ws: bool,
    spk_override: Option<Vec<u8>>,
}

impl M8In {
    fn new(ws: &[u8], amount: u64, salt: u8) -> Self {
        Self {
            ws: ws.to_vec(),
            amount,
            salt,
            records: Vec::new(),
            omit_ws: false,
            spk_override: None,
        }
    }

    fn with(mut self, r: Vec<u8>) -> Self {
        self.records.push(r);
        self
    }
}

fn m8_prevtx(spec: &M8In) -> Vec<u8> {
    let spk = spec.spk_override.clone().unwrap_or_else(|| p2wsh(&spec.ws));
    prevtx_legacy(spec.salt, 1, &[], &[(spec.amount, spk)])
}

fn m8_psbt(specs: &[M8In], outs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let ins: Vec<([u8; 32], u32)> = specs
        .iter()
        .map(|s| (oracle_sha256d(&m8_prevtx(s)), 0))
        .collect();
    let unsigned = unsigned_tx(&ins, outs);
    let maps: Vec<Vec<Vec<u8>>> = specs
        .iter()
        .map(|s| {
            let mut m = vec![r_nwutxo(&m8_prevtx(s))];
            if !s.omit_ws {
                m.push(r_wscript(&s.ws));
            }
            m.extend(s.records.iter().cloned());
            m
        })
        .collect();
    psbt(&unsigned, &maps, outs.len())
}

/// BIP143 SIGHASH_ALL digest for input `index` of the fixture that
/// `m8_psbt` produces (version 2, all vouts 0, sequence 0xffffffff,
/// locktime 0), computed through the crate's KAT-anchored engine.
fn m8_digest(specs: &[M8In], outs: &[(u64, Vec<u8>)], index: usize) -> [u8; 32] {
    use qk_psbt::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder};
    let txids: Vec<[u8; 32]> = specs
        .iter()
        .map(|s| oracle_sha256d(&m8_prevtx(s)))
        .collect();
    let mut b = Bip143PrecomputeBuilder::new();
    for t in &txids {
        b.add_input(t, 0, 0xffff_ffff).unwrap();
    }
    for (amount, script) in outs {
        b.add_output(*amount, script).unwrap();
    }
    let pre = b.finish().unwrap();
    sighash_all_digest(
        2,
        0,
        &pre,
        &Bip143InputFacts {
            outpoint_txid_wire: &txids[index],
            outpoint_vout: 0,
            script_code: &specs[index].ws,
            amount_sats: specs[index].amount,
            sequence: 0xffff_ffff,
        },
    )
    .unwrap()
}

type M8Outcome = (Vec<(usize, VerifiedInputStatus)>, VerifiedAggregateStatus);

fn m8_run(bytes: &[u8]) -> Result<M8Outcome, SemanticError> {
    let view = parse(bytes, InputSource::MicroSd).expect("fixture must parse");
    analyze_and_verify_signatures(&view).map(|v| {
        (
            v.verified_inputs
                .iter()
                .map(|f| (f.verified_signature_count, f.status))
                .collect(),
            v.aggregate_status,
        )
    })
}

fn m8_err(bytes: &[u8]) -> SemanticError {
    m8_run(bytes).expect_err("expected M8 rejection")
}

// ---------------------------------------------------------------
// M8 tests.
// ---------------------------------------------------------------

#[test]
fn m8_public_fixture_table_cross_checked_through_qk_secp() {
    // Every fixture signature is checked through the qk-secp
    // verification boundary: it must verify for exactly its own
    // (key, digest) pair, fail for a mutated digest, and fail for a
    // different table key; high-S companions must parse and reject;
    // no two fixtures for distinct key/digest pairs may share a DER
    // r value (nonce-reuse screen). These checks and the
    // source-symbol scan are necessary screens, not a proof that no
    // key-like material is present in the committed values.
    let ws3 = wscript(2, &[fx_pk(0), fx_pk(1), fx_pk(2)]);
    let ws2 = wscript(2, &[fx_pk(0), fx_pk(1)]);
    let mut fake = [0xabu8; 33];
    fake[0] = 0x02;
    let ws_fake = wscript(2, &[fx_pk(0), fx_pk(1), fake]);
    let ws_off = wscript(2, &[fx_pk(0), fx_pk(1), M8_OFFCURVE_PK]);
    let keys15: Vec<[u8; 33]> = (0..15).map(fx_pk).collect();
    let ws15 = wscript(15, &keys15);
    let outs1 = vec![(80_000u64, spk())];
    let single = |ws: &[u8], salt: u8| m8_digest(&[M8In::new(ws, 100_000, salt)], &outs1, 0);

    let outs_ag = vec![(120_000u64, spk())];
    let specs_ag = [
        M8In::new(&ws3, 100_000, 0x31),
        M8In::new(&ws3, 90_000, 0x32),
    ];

    // Sensitivity fixture digests (two committed prevouts on the
    // first prevtx; matches m8_end_to_end_digest_sensitivity).
    let sens = |index: usize| {
        use qk_psbt::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder};
        let prev_a = prevtx_legacy(
            0x91,
            1,
            &[],
            &[(60_000, p2wsh(&ws2)), (60_001, p2wsh(&ws2))],
        );
        let prev_b = prevtx_legacy(0x92, 1, &[], &[(40_000, p2wsh(&ws2))]);
        let ins = [
            (oracle_sha256d(&prev_a), 0u32, 0xffff_ffffu32),
            (oracle_sha256d(&prev_b), 0, 0xffff_ffff),
        ];
        let amounts = [60_000u64, 40_000];
        let mut b = Bip143PrecomputeBuilder::new();
        for (txid, vout, sequence) in &ins {
            b.add_input(txid, *vout, *sequence).unwrap();
        }
        b.add_output(50_000, &spk()).unwrap();
        b.add_output(30_000, &spk()).unwrap();
        let pre = b.finish().unwrap();
        sighash_all_digest(
            2,
            0,
            &pre,
            &Bip143InputFacts {
                outpoint_txid_wire: &ins[index].0,
                outpoint_vout: ins[index].1,
                script_code: &ws2,
                amount_sats: amounts[index],
                sequence: ins[index].2,
            },
        )
        .unwrap()
    };

    let d_cross = [0x42u8; 32];
    let d_thresh = single(&ws3, 0x21);
    let d_agg0 = m8_digest(&specs_ag, &outs_ag, 0);
    let d_agg1 = m8_digest(&specs_ag, &outs_ag, 1);
    let d_final = single(&ws2, 0x42);
    let d_fake = single(&ws_fake, 0x53);
    let d_memb = single(&ws3, 0x71);
    let d_off = single(&ws_off, 0x72);
    let d_15 = single(&ws15, 0x81);
    let d_sens0 = sens(0);
    let d_sens1 = sens(1);
    let d_det = single(&ws3, 0xa1);

    // Every committed low-S signature with its exact key and digest;
    // each row is a distinct (key, digest) pair.
    let mut table: Vec<(&[u8], usize, [u8; 32])> = Vec::new();
    for (j, &i) in [0usize, 1, 2, 14].iter().enumerate() {
        table.push((SIG_CROSS[j], i, d_cross));
    }
    for (i, sig) in SIG_THRESH.iter().enumerate() {
        table.push((sig, i, d_thresh));
    }
    for (i, sig) in SIG_AGG0.iter().enumerate() {
        table.push((sig, i, d_agg0));
    }
    for (i, sig) in SIG_AGG1.iter().enumerate() {
        table.push((sig, i, d_agg1));
    }
    for (i, sig) in SIG_FINAL.iter().enumerate() {
        table.push((sig, i, d_final));
    }
    for (i, sig) in SIG_FAKEMEM.iter().enumerate() {
        table.push((sig, i, d_fake));
    }
    for (i, sig) in SIG_MEMB.iter().enumerate() {
        table.push((sig, i, d_memb));
    }
    table.push((SIG_MEMB_NONMEMBER, 7, d_memb));
    table.push((SIG_OFFCURVE_WS, 3, d_off));
    for (i, sig) in SIG_FIFTEEN.iter().enumerate() {
        table.push((sig, i, d_15));
    }
    for (i, sig) in SIG_SENS0.iter().enumerate() {
        table.push((sig, i, d_sens0));
    }
    for (i, sig) in SIG_SENS1.iter().enumerate() {
        table.push((sig, i, d_sens1));
    }
    for (i, sig) in SIG_DET.iter().enumerate() {
        table.push((sig, i, d_det));
    }
    assert_eq!(table.len(), 40);

    let mut r_values: Vec<Vec<u8>> = Vec::new();
    for (n, (sig, key, digest)) in table.iter().enumerate() {
        let pubkey =
            qk_secp::pubkey_parse_compressed(&fx_pk(*key)).expect("fixture pubkey on curve");
        assert_eq!(sig.last(), Some(&0x01), "fixture {n}");
        let parsed = qk_secp::signature_parse_der(&sig[..sig.len() - 1]).expect("strict DER");
        qk_secp::ecdsa_verify(&parsed, digest, &pubkey)
            .expect("fixture verifies for its own key and digest");
        let mut wrong = *digest;
        wrong[0] ^= 0xff;
        assert!(
            qk_secp::ecdsa_verify(&parsed, &wrong, &pubkey).is_err(),
            "fixture {n} must fail a mutated digest"
        );
        let other_key = qk_secp::pubkey_parse_compressed(&fx_pk((key + 1) % 15)).unwrap();
        assert!(
            qk_secp::ecdsa_verify(&parsed, digest, &other_key).is_err(),
            "fixture {n} must fail a different key"
        );
        // DER r component (0x30 len 0x02 rlen r ...): reuse screen.
        assert_eq!(sig[2], 0x02, "fixture {n}");
        let rlen = sig[3] as usize;
        let r = sig[4..4 + rlen].to_vec();
        assert!(
            !r_values.contains(&r),
            "fixture {n}: distinct key/digest fixtures share a DER r value"
        );
        r_values.push(r);
    }

    // High-S companions parse but never verify.
    for (j, &i) in [0usize, 1, 2, 14].iter().enumerate() {
        let pubkey = qk_secp::pubkey_parse_compressed(&fx_pk(i)).unwrap();
        let high = SIG_CROSS_HIGH[j];
        let parsed =
            qk_secp::signature_parse_der(&high[..high.len() - 1]).expect("high-S DER parses");
        assert!(qk_secp::ecdsa_verify(&parsed, &d_cross, &pubkey).is_err());
    }
    let memb_high = qk_secp::signature_parse_der(&SIG_MEMB_HIGH[..SIG_MEMB_HIGH.len() - 1])
        .expect("high-S DER parses");
    assert!(qk_secp::ecdsa_verify(
        &memb_high,
        &d_memb,
        &qk_secp::pubkey_parse_compressed(&fx_pk(0)).unwrap()
    )
    .is_err());

    // Every table pubkey parses on-curve and is distinct; the
    // off-curve fixture is rejected at the qk-secp boundary.
    let distinct: std::collections::HashSet<[u8; 33]> = (0..15).map(fx_pk).collect();
    assert_eq!(distinct.len(), 15);
    for i in 0..15 {
        qk_secp::pubkey_parse_compressed(&fx_pk(i)).expect("table pubkey on curve");
    }
    assert!(qk_secp::pubkey_parse_compressed(&M8_OFFCURVE_PK).is_err());
}

#[test]
fn m8_verified_counts_and_threshold_single_input() {
    let keys = [fx_pk(0), fx_pk(1), fx_pk(2)];
    let ws = wscript(2, &keys);
    let outs = vec![(80_000u64, spk())];
    let base = M8In::new(&ws, 100_000, 0x21);
    let cases: Vec<(
        Vec<usize>,
        usize,
        VerifiedInputStatus,
        VerifiedAggregateStatus,
    )> = vec![
        (
            vec![],
            0,
            VerifiedInputStatus::BelowThreshold,
            VerifiedAggregateStatus::AllInputsBelowThreshold,
        ),
        (
            vec![0],
            1,
            VerifiedInputStatus::BelowThreshold,
            VerifiedAggregateStatus::AllInputsBelowThreshold,
        ),
        (
            vec![0, 1],
            2,
            VerifiedInputStatus::CryptographicallyVerifiedThreshold,
            VerifiedAggregateStatus::VerifyAndExportOnly,
        ),
        (
            vec![0, 1, 2],
            3,
            VerifiedInputStatus::CryptographicallyVerifiedThreshold,
            VerifiedAggregateStatus::VerifyAndExportOnly,
        ),
    ];
    for (signers, count, status, aggregate) in cases {
        let mut spec = base.clone();
        for &i in &signers {
            spec = spec.with(r_sig(&fx_pk(i), SIG_THRESH[i]));
        }
        let bytes = m8_psbt(&[spec], &outs);
        let (inputs, agg) = m8_run(&bytes).expect("verified analysis succeeds");
        assert_eq!(inputs, vec![(count, status)], "signers {signers:?}");
        assert_eq!(agg, aggregate, "signers {signers:?}");
        // The M6 entrypoint stays available and unchanged on the same
        // bytes, and the embedded candidate matches its output.
        let view = parse(&bytes, InputSource::MicroSd).unwrap();
        let m6 = analyze_semantic_subset(&view).unwrap();
        let verified = analyze_and_verify_signatures(&view).unwrap();
        assert_eq!(verified.candidate.fee, m6.fee);
        assert_eq!(verified.candidate.inputs.len(), m6.inputs.len());
        assert_eq!(
            verified.candidate.inputs[0].structural_signature_candidates,
            m6.inputs[0].structural_signature_candidates
        );
        assert_eq!(
            verified.candidate.inputs[0].signature_status,
            m6.inputs[0].signature_status
        );
        canonical_serialize(&view).expect("serializer unaffected");
    }
}

#[test]
fn m8_aggregate_statuses_multi_input() {
    let keys = [fx_pk(0), fx_pk(1), fx_pk(2)];
    let ws = wscript(2, &keys);
    let outs = vec![(120_000u64, spk())];
    let base = [M8In::new(&ws, 100_000, 0x31), M8In::new(&ws, 90_000, 0x32)];
    let d0 = m8_digest(&base, &outs, 0);
    let d1 = m8_digest(&base, &outs, 1);
    assert_ne!(d0, d1, "per-input digests must differ");
    let signed = |spec: &M8In, sigs: &[&[u8]; 2]| {
        spec.clone()
            .with(r_sig(&fx_pk(0), sigs[0]))
            .with(r_sig(&fx_pk(1), sigs[1]))
    };
    let threshold = VerifiedInputStatus::CryptographicallyVerifiedThreshold;
    let below = VerifiedInputStatus::BelowThreshold;

    let all = m8_psbt(
        &[signed(&base[0], &SIG_AGG0), signed(&base[1], &SIG_AGG1)],
        &outs,
    );
    let (inputs, agg) = m8_run(&all).unwrap();
    assert_eq!(inputs, vec![(2, threshold), (2, threshold)]);
    assert_eq!(agg, VerifiedAggregateStatus::VerifyAndExportOnly);

    let mixed = m8_psbt(&[signed(&base[0], &SIG_AGG0), base[1].clone()], &outs);
    let (inputs, agg) = m8_run(&mixed).unwrap();
    assert_eq!(inputs, vec![(2, threshold), (0, below)]);
    assert_eq!(agg, VerifiedAggregateStatus::MixedInputCompleteness);

    let none = m8_psbt(&base, &outs);
    let (inputs, agg) = m8_run(&none).unwrap();
    assert_eq!(inputs, vec![(0, below), (0, below)]);
    assert_eq!(agg, VerifiedAggregateStatus::AllInputsBelowThreshold);
}

#[test]
fn m8_screen_missing_witness_script_and_final_fields() {
    let keys = [fx_pk(0), fx_pk(1)];
    let ws = wscript(2, &keys);
    let outs = vec![(80_000u64, spk())];
    // Missing witnessScript: M8 rejects with its own fixed category;
    // M6 still accepts the same bytes structurally.
    let mut spec = M8In::new(&ws, 100_000, 0x41);
    spec.omit_ws = true;
    let bytes = m8_psbt(&[spec], &outs);
    let e = m8_err(&bytes);
    assert_eq!(e.category, SemanticCategory::MissingWitnessScript);
    assert_eq!(e.input_index, Some(0));
    assert_ok(&bytes);
    // Final-script fields are unsupported for verification even when
    // the threshold would otherwise verify; M6 accepts them.
    let base = M8In::new(&ws, 100_000, 0x42);
    for final_rec in [rec(&[0x07], &[0x51]), rec(&[0x08], &[0x01, 0x00])] {
        let spec = base
            .clone()
            .with(r_sig(&fx_pk(0), SIG_FINAL[0]))
            .with(r_sig(&fx_pk(1), SIG_FINAL[1]))
            .with(final_rec);
        let bytes = m8_psbt(&[spec], &outs);
        let e = m8_err(&bytes);
        assert_eq!(e.category, SemanticCategory::UnsupportedFinalScriptFields);
        assert_eq!(e.input_index, Some(0));
        assert_ok(&bytes);
    }
}

#[test]
fn m8_codeseparator_opcode_rejected_pushed_byte_allowed() {
    let outs = vec![(80_000u64, spk())];
    // An actual OP_CODESEPARATOR (0xAB) opcode inside the script.
    let keys = [fx_pk(0), fx_pk(1)];
    let mut ws_sep = vec![0x52];
    for k in &keys {
        ws_sep.push(0x21);
        ws_sep.extend_from_slice(k);
    }
    ws_sep.push(0xab);
    ws_sep.push(0x52);
    ws_sep.push(0xae);
    let bytes = m8_psbt(&[M8In::new(&ws_sep, 100_000, 0x51)], &outs);
    assert_eq!(
        m8_err(&bytes).category,
        SemanticCategory::UnsupportedCodeSeparator
    );
    // Frozen M8 precedence: CodeSeparator beats unsupported sighash;
    // the frozen M6 precedence on the same bytes is unchanged.
    let spec = M8In::new(&ws_sep, 100_000, 0x52).with(r_sighash(3));
    let bytes = m8_psbt(&[spec], &outs);
    assert_eq!(
        m8_err(&bytes).category,
        SemanticCategory::UnsupportedCodeSeparator
    );
    assert_eq!(
        analyze_err(&bytes).category,
        SemanticCategory::UnsupportedSighash
    );
    // A pushed 0xAB data byte never matches: a fake member key made
    // of 0xAB bytes is push data, and the real threshold verifies.
    let mut fake = [0xabu8; 33];
    fake[0] = 0x02;
    let member_keys = [fx_pk(0), fx_pk(1), fake];
    let ws = wscript(2, &member_keys);
    let spec = M8In::new(&ws, 100_000, 0x53)
        .with(r_sig(&fx_pk(0), SIG_FAKEMEM[0]))
        .with(r_sig(&fx_pk(1), SIG_FAKEMEM[1]));
    let (inputs, agg) = m8_run(&m8_psbt(&[spec], &outs)).unwrap();
    assert_eq!(
        inputs,
        vec![(2, VerifiedInputStatus::CryptographicallyVerifiedThreshold)]
    );
    assert_eq!(agg, VerifiedAggregateStatus::VerifyAndExportOnly);
}

#[test]
fn m8_native_p2wsh_and_route_matrix() {
    let keys = [fx_pk(0), fx_pk(1)];
    let ws = wscript(2, &keys);
    let other_ws = wscript(1, &[fx_pk(2)]);
    let outs = vec![(80_000u64, spk())];
    // The exact native commitment is accepted (below threshold).
    let bytes = m8_psbt(&[M8In::new(&ws, 100_000, 0x61)], &outs);
    let (inputs, agg) = m8_run(&bytes).unwrap();
    assert_eq!(inputs, vec![(0, VerifiedInputStatus::BelowThreshold)]);
    assert_eq!(agg, VerifiedAggregateStatus::AllInputsBelowThreshold);
    // Wrong-script commitment, non-native P2WPKH, and wrapped P2SH
    // prevouts all reject with one fixed category; M6 accepts each.
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0x77; 20]);
    p2sh.push(0x87);
    for bad_spk in [p2wsh(&other_ws), spk(), p2sh] {
        let mut spec = M8In::new(&ws, 100_000, 0x62);
        spec.spk_override = Some(bad_spk);
        let bytes = m8_psbt(&[spec], &outs);
        let e = m8_err(&bytes);
        assert_eq!(
            e.category,
            SemanticCategory::PrevoutNotNativeWitnessScriptHash
        );
        assert_eq!(e.input_index, Some(0));
        assert_ok(&bytes);
    }
    // A redeem-script record (wrapped route) is rejected even with a
    // correct native commitment; M6 accepts it.
    let spec = M8In::new(&ws, 100_000, 0x63).with(rec(&[0x04], &[0x51]));
    let bytes = m8_psbt(&[spec], &outs);
    assert_eq!(
        m8_err(&bytes).category,
        SemanticCategory::UnsupportedRedeemScriptRoute
    );
    assert_ok(&bytes);
    // An unsigned output scriptPubKey at the structural cap (the
    // parser rejects anything longer before analysis can run) flows
    // through the digest engine without tripping its invariant.
    let big_outs = vec![(80_000u64, vec![0x00; 10_000])];
    let bytes = m8_psbt(&[M8In::new(&ws, 100_000, 0x64)], &big_outs);
    let (inputs, agg) = m8_run(&bytes).unwrap();
    assert_eq!(inputs, vec![(0, VerifiedInputStatus::BelowThreshold)]);
    assert_eq!(agg, VerifiedAggregateStatus::AllInputsBelowThreshold);
    assert_ok(&bytes);
}

#[test]
fn m8_membership_pubkey_and_signature_matrix() {
    let keys = [fx_pk(0), fx_pk(1), fx_pk(2)];
    let ws = wscript(2, &keys);
    let outs = vec![(80_000u64, spk())];
    let base = M8In::new(&ws, 100_000, 0x71);
    // A non-member pubkey record rejects even alongside a complete
    // valid threshold; M6 counts members only and accepts.
    let spec = base
        .clone()
        .with(r_sig(&fx_pk(0), SIG_MEMB[0]))
        .with(r_sig(&fx_pk(1), SIG_MEMB[1]))
        .with(r_sig(&fx_pk(7), SIG_MEMB_NONMEMBER));
    let bytes = m8_psbt(&[spec], &outs);
    let e = m8_err(&bytes);
    assert_eq!(
        e.category,
        SemanticCategory::PartialSignaturePubkeyNotInWitnessScript
    );
    assert_eq!(e.input_index, Some(0));
    assert_ok(&bytes);
    // A member's valid fixed signature over different facts (the
    // cross-check digest) is a wrong-digest signature here: rejects.
    let spec = base.clone().with(r_sig(&fx_pk(0), SIG_CROSS[0]));
    assert_eq!(
        m8_err(&m8_psbt(&[spec], &outs)).category,
        SemanticCategory::SignatureVerificationFailed
    );
    // One invalid extra signature rejects even when m good signatures
    // exist, wherever it sits in map order.
    let spec = base
        .clone()
        .with(r_sig(&fx_pk(0), SIG_MEMB[0]))
        .with(r_sig(&fx_pk(1), SIG_MEMB[1]))
        .with(r_sig(&fx_pk(2), SIG_CROSS[2]));
    let bytes = m8_psbt(&[spec], &outs);
    assert_eq!(
        m8_err(&bytes).category,
        SemanticCategory::SignatureVerificationFailed
    );
    assert_ok(&bytes);
    let spec = base
        .clone()
        .with(r_sig(&fx_pk(0), SIG_CROSS[0]))
        .with(r_sig(&fx_pk(1), SIG_MEMB[1]));
    assert_eq!(
        m8_err(&m8_psbt(&[spec], &outs)).category,
        SemanticCategory::SignatureVerificationFailed
    );
    // A foreign signature (member 0's valid signature under member
    // pubkey 1) rejects.
    let spec = base.clone().with(r_sig(&fx_pk(1), SIG_MEMB[0]));
    assert_eq!(
        m8_err(&m8_psbt(&[spec], &outs)).category,
        SemanticCategory::SignatureVerificationFailed
    );
    // An off-curve member pubkey with a signature record: membership
    // passes, cryptographic parsing fails.
    let ws_off = wscript(2, &[fx_pk(0), fx_pk(1), M8_OFFCURVE_PK]);
    let spec = M8In::new(&ws_off, 100_000, 0x72).with(r_sig(&M8_OFFCURVE_PK, SIG_OFFCURVE_WS));
    assert_eq!(
        m8_err(&m8_psbt(&[spec], &outs)).category,
        SemanticCategory::InvalidCryptographicPubkey
    );
    // Malformed DER and high-S records keep their M6 categories in
    // both entrypoints.
    let spec = base.clone().with(r_sig(&fx_pk(0), &[0xff; 40]));
    let bytes = m8_psbt(&[spec], &outs);
    assert_eq!(m8_err(&bytes).category, SemanticCategory::StrictDer);
    assert_eq!(analyze_err(&bytes).category, SemanticCategory::StrictDer);
    let spec = base.clone().with(r_sig(&fx_pk(0), SIG_MEMB_HIGH));
    let bytes = m8_psbt(&[spec], &outs);
    assert_eq!(m8_err(&bytes).category, SemanticCategory::HighS);
    assert_eq!(analyze_err(&bytes).category, SemanticCategory::HighS);
}

#[test]
fn m8_fifteen_of_fifteen_threshold() {
    let keys: Vec<[u8; 33]> = (0..15).map(fx_pk).collect();
    let ws = wscript(15, &keys);
    let outs = vec![(80_000u64, spk())];
    let mut spec = M8In::new(&ws, 100_000, 0x81);
    for (i, sig) in SIG_FIFTEEN.iter().enumerate() {
        spec = spec.with(r_sig(&fx_pk(i), sig));
    }
    let (inputs, agg) = m8_run(&m8_psbt(&[spec], &outs)).unwrap();
    assert_eq!(
        inputs,
        vec![(15, VerifiedInputStatus::CryptographicallyVerifiedThreshold)]
    );
    assert_eq!(agg, VerifiedAggregateStatus::VerifyAndExportOnly);
}

/// Unsigned tx with explicit version, per-input sequence, and
/// locktime (the shared builder pins all three).
fn unsigned_tx_v(
    version: u32,
    ins: &[([u8; 32], u32, u32)],
    outs: &[(u64, Vec<u8>)],
    locktime: u32,
) -> Vec<u8> {
    let mut v = version.to_le_bytes().to_vec();
    v.extend_from_slice(&cs(ins.len() as u64));
    for (txid, vout, sequence) in ins {
        v.extend_from_slice(txid);
        v.extend_from_slice(&vout.to_le_bytes());
        v.push(0x00);
        v.extend_from_slice(&sequence.to_le_bytes());
    }
    v.extend_from_slice(&cs(outs.len() as u64));
    for (amount, script) in outs {
        v.extend_from_slice(&amount.to_le_bytes());
        v.extend_from_slice(&cs(script.len() as u64));
        v.extend_from_slice(script);
    }
    v.extend_from_slice(&locktime.to_le_bytes());
    v
}

#[test]
fn m8_end_to_end_digest_sensitivity() {
    let keys = [fx_pk(0), fx_pk(1)];
    let ws = wscript(2, &keys);
    // Two committed prevouts on the first prevtx (amounts differ) so
    // an in-range vout change is purely a digest-input change.
    let prev_a = prevtx_legacy(0x91, 1, &[], &[(60_000, p2wsh(&ws)), (60_001, p2wsh(&ws))]);
    let txid_a = oracle_sha256d(&prev_a);
    let prev_b = prevtx_legacy(0x92, 1, &[], &[(40_000, p2wsh(&ws))]);
    let txid_b = oracle_sha256d(&prev_b);
    let outs = vec![(50_000u64, spk()), (30_000u64, spk())];
    let base_ins = [(txid_a, 0u32, 0xffff_ffffu32), (txid_b, 0, 0xffff_ffff)];

    let sigs0 = [
        r_sig(&fx_pk(0), SIG_SENS0[0]),
        r_sig(&fx_pk(1), SIG_SENS0[1]),
    ];
    let sigs1 = [
        r_sig(&fx_pk(0), SIG_SENS1[0]),
        r_sig(&fx_pk(1), SIG_SENS1[1]),
    ];
    let build =
        |version: u32, ins: &[([u8; 32], u32, u32)], outs: &[(u64, Vec<u8>)], locktime: u32| {
            let unsigned = unsigned_tx_v(version, ins, outs, locktime);
            let mut map0 = vec![r_nwutxo(&prev_a), r_wscript(&ws)];
            map0.extend(sigs0.iter().cloned());
            let mut map1 = vec![r_nwutxo(&prev_b), r_wscript(&ws)];
            map1.extend(sigs1.iter().cloned());
            psbt(&unsigned, &[map0, map1], outs.len())
        };
    // The baseline verifies completely.
    let threshold = VerifiedInputStatus::CryptographicallyVerifiedThreshold;
    let (inputs, agg) = m8_run(&build(2, &base_ins, &outs, 0)).unwrap();
    assert_eq!(inputs, vec![(2, threshold), (2, threshold)]);
    assert_eq!(agg, VerifiedAggregateStatus::VerifyAndExportOnly);
    // Every single digest-input mutation flips verification into the
    // fixed signature-verification rejection.
    let mut vout_flip = base_ins;
    vout_flip[0].1 = 1; // outpoint vout + verified amount change
    let mut seq_flip = base_ins;
    seq_flip[1].2 = 0xffff_fffe; // second input sequence
    let mut amount_out = outs.clone();
    amount_out[0].0 = 49_999; // first output amount
    let mut script_out = outs.clone();
    script_out[1].1[5] = 0xbb; // second output scriptPubKey
    let mutations = [
        build(1, &base_ins, &outs, 0), // version
        build(2, &base_ins, &outs, 1), // locktime
        build(2, &vout_flip, &outs, 0),
        build(2, &seq_flip, &outs, 0),
        build(2, &base_ins, &amount_out, 0),
        build(2, &base_ins, &script_out, 0),
    ];
    for (case, bytes) in mutations.iter().enumerate() {
        let e = m8_err(bytes);
        assert_eq!(
            e.category,
            SemanticCategory::SignatureVerificationFailed,
            "mutation {case}"
        );
        assert_eq!(e.input_index, Some(0), "mutation {case}");
    }
}

#[test]
fn m8_deterministic_and_no_panic_under_mutation() {
    let keys = [fx_pk(0), fx_pk(1), fx_pk(2)];
    let ws = wscript(2, &keys);
    let outs = vec![(80_000u64, spk())];
    let spec = M8In::new(&ws, 100_000, 0xa1)
        .with(r_sig(&fx_pk(0), SIG_DET[0]))
        .with(r_sig(&fx_pk(1), SIG_DET[1]));
    let bytes = m8_psbt(&[spec], &outs);
    assert!(m8_run(&bytes).is_ok());
    let describe = |b: &[u8]| match parse(b, InputSource::MicroSd) {
        Err(e) => format!("parse:{e:?}"),
        Ok(view) => match analyze_and_verify_signatures(&view) {
            Ok(v) => format!(
                "ok:{:?}:{:?}",
                v.aggregate_status,
                v.verified_inputs
                    .iter()
                    .map(|f| (f.verified_signature_count, f.status))
                    .collect::<Vec<_>>()
            ),
            Err(e) => format!("err:{}:{:?}:{}", e.category, e.input_index, e.offset),
        },
    };
    for i in 0..bytes.len() {
        let mut m = bytes.clone();
        m[i] ^= 0x01;
        assert_eq!(describe(&m), describe(&m), "byte {i} nondeterministic");
    }
    for len in 0..bytes.len() {
        let t = &bytes[..len];
        assert_eq!(
            describe(t),
            describe(t),
            "truncation {len} nondeterministic"
        );
    }
}

#[test]
fn m8_fixed_error_text_and_stable_location() {
    let keys = [fx_pk(0), fx_pk(1)];
    let ws = wscript(2, &keys);
    let outs = vec![(80_000u64, spk())];
    let mut spec = M8In::new(&ws, 100_000, 0xb1);
    spec.omit_ws = true;
    let bytes = m8_psbt(&[spec], &outs);
    let first = m8_err(&bytes);
    let second = m8_err(&bytes);
    assert_eq!(first, second, "error must be byte-for-byte stable");
    assert_eq!(
        first.category.to_string(),
        "missing witness script for signature verification"
    );
    // Fixed text only for every new category: no fixture bytes ever
    // appear in the rendered error.
    let rendered = [
        SemanticCategory::MissingWitnessScript.to_string(),
        SemanticCategory::UnsupportedFinalScriptFields.to_string(),
        SemanticCategory::UnsupportedRedeemScriptRoute.to_string(),
        SemanticCategory::UnsupportedCodeSeparator.to_string(),
        SemanticCategory::PrevoutNotNativeWitnessScriptHash.to_string(),
        SemanticCategory::PartialSignaturePubkeyNotInWitnessScript.to_string(),
        SemanticCategory::InvalidCryptographicPubkey.to_string(),
        SemanticCategory::SignatureVerificationFailed.to_string(),
        SemanticCategory::CryptographicBackendInvariant.to_string(),
    ];
    for text in &rendered {
        assert!(text.is_ascii());
        assert!(!text.contains("0x"));
        assert!(text.chars().all(|c| c.is_ascii_lowercase() || c == ' '));
    }
    assert_eq!(
        rendered.len(),
        rendered
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        "category texts must be distinct"
    );
}

#[test]
fn m8_no_private_or_signing_helper_symbols_in_tests() {
    // The banned symbol names are assembled at runtime so this scan
    // can never match its own source text. It fails if any signer,
    // scalar, nonce, curve-arithmetic, or DER-generation helper from
    // a private-input signing implementation reappears in this file.
    // This is a spelling-level screen only: it is necessary but not
    // sufficient, and it does not by itself prove the absence of
    // key-like material in the committed fixture values.
    let src = include_str!("semantic.rs");
    let banned = [
        ["m8_", "sign"].concat(),
        ["m8_", "pubkey"].concat(),
        ["SECP", "_P"].concat(),
        ["SECP", "_N"].concat(),
        ["SECP", "_G"].concat(),
        ["U", "256"].concat(),
        ["u_", "sub"].concat(),
        ["der", "_int"].concat(),
        ["off_curve", "_pubkey"].concat(),
        ["private", " scalar"].concat(),
        ["fixed nonce", " k"].concat(),
    ];
    for b in &banned {
        assert_eq!(
            src.matches(b.as_str()).count(),
            0,
            "banned private/signing helper symbol present: {b}"
        );
    }
}
