//! Structural tests: caps, CompactSize boundaries, scope policy,
//! duplicate keys, truncation at every byte boundary, verbatim
//! preservation, malformed transactions, map counts, determinism.
//! HOST evidence only; synthetic bytes; no secrets; no conformance claim.

use qk_psbt::{limits, parse, InputSource, RejectCategory};

/// Minimal CompactSize encoding.
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

/// One record from raw key bytes (type already encoded) and value.
fn rec_raw(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut b = cs(key.len() as u64);
    b.extend_from_slice(key);
    b.extend_from_slice(&cs(value.len() as u64));
    b.extend_from_slice(value);
    b
}

/// One record from a numeric key type, key data, and value.
fn rec(key_type: u64, key_data: &[u8], value: &[u8]) -> Vec<u8> {
    let mut key = cs(key_type);
    key.extend_from_slice(key_data);
    rec_raw(&key, value)
}

/// Minimal structurally valid unsigned transaction.
fn tx(n_in: usize, n_out: usize) -> Vec<u8> {
    let mut b = vec![2, 0, 0, 0];
    b.extend_from_slice(&cs(n_in as u64));
    for i in 0..n_in {
        b.extend_from_slice(&[i as u8; 32]);
        b.extend_from_slice(&(i as u32).to_le_bytes());
        b.push(0); // empty scriptSig
        b.extend_from_slice(&[0xff; 4]);
    }
    b.extend_from_slice(&cs(n_out as u64));
    for _ in 0..n_out {
        b.extend_from_slice(&[0u8; 8]);
        b.extend_from_slice(&[1, 0x51]); // one-byte script
    }
    b.extend_from_slice(&[0; 4]); // locktime
    b
}

/// Assemble a PSBT: magic, unsigned tx record, extra global records,
/// then per-input and per-output maps.
fn build(global_extra: &[Vec<u8>], inputs: &[Vec<Vec<u8>>], outputs: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut b = b"psbt\xff".to_vec();
    b.extend_from_slice(&rec(0x00, &[], &tx(inputs.len(), outputs.len())));
    for r in global_extra {
        b.extend_from_slice(r);
    }
    b.push(0);
    for m in inputs {
        for r in m {
            b.extend_from_slice(r);
        }
        b.push(0);
    }
    for m in outputs {
        for r in m {
            b.extend_from_slice(r);
        }
        b.push(0);
    }
    b
}

fn minimal() -> Vec<u8> {
    build(&[], &[vec![]], &[vec![]])
}

fn p(buf: &[u8]) -> Result<qk_psbt::PsbtView<'_>, qk_psbt::ParseError> {
    parse(buf, InputSource::MicroSd)
}

fn cat(buf: &[u8]) -> RejectCategory {
    p(buf).expect_err("expected rejection").category
}

fn pubkey(tag: u8) -> Vec<u8> {
    let mut k = vec![0x02];
    k.extend_from_slice(&[tag; 32]);
    k
}

fn bip32_value(depth: usize) -> Vec<u8> {
    let mut v = vec![0xaa; 4];
    for i in 0..depth {
        v.extend_from_slice(&(i as u32).to_le_bytes());
    }
    v
}

// --- basic acceptance and view facts ------------------------------------

#[test]
fn minimal_psbt_accepts_with_expected_view_facts() {
    let b = minimal();
    let v = p(&b).expect("minimal PSBT must parse");
    assert_eq!(v.unsigned_tx().input_count, 1);
    assert_eq!(v.unsigned_tx().output_count, 1);
    assert_eq!(v.input_map_count(), 1);
    assert_eq!(v.output_map_count(), 1);
    assert_eq!(v.global_map_span().start, 5);
    assert_eq!(v.output_map_span(0).unwrap().end, b.len());
    assert_eq!(v.unsigned_tx_bytes(), &tx(1, 1)[..]);
    let recs: Vec<_> = v.global_records().collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].key_type, 0x00);
    assert_eq!(v.input_records(0).unwrap().count(), 0);
    assert_eq!(v.output_records(0).unwrap().count(), 0);
    assert!(v.input_records(1).is_none());
}

#[test]
fn empty_and_missing_magic_reject() {
    assert_eq!(cat(&[]), RejectCategory::Truncated);
    assert_eq!(cat(b"psb"), RejectCategory::Truncated);
    assert_eq!(cat(b"psbt\x00rest"), RejectCategory::InvalidMagic);
    assert_eq!(cat(b"xsbt\xffrest"), RejectCategory::InvalidMagic);
}

// --- source byte caps ----------------------------------------------------

#[test]
fn source_byte_caps_enforced_at_exact_boundary() {
    // Pad a valid PSBT to exactly the SD cap with one unknown record.
    // Replacing the empty value with a pad-length value swaps a 1-byte
    // CompactSize for a 5-byte one and adds the pad bytes.
    let base = build(&[rec(0xf0, &[], &[])], &[vec![]], &[vec![]]);
    let pad = limits::MAX_SD_INPUT_BYTES - base.len() - 4;
    let exact = build(&[rec(0xf0, &[], &vec![0u8; pad])], &[vec![]], &[vec![]]);
    assert_eq!(exact.len(), limits::MAX_SD_INPUT_BYTES);
    assert!(parse(&exact, InputSource::MicroSd).is_ok());
    assert_eq!(
        parse(&exact, InputSource::Qr).err().unwrap().category,
        RejectCategory::InputTooLarge
    );
    let over = build(&[rec(0xf0, &[], &vec![0u8; pad + 1])], &[vec![]], &[vec![]]);
    assert_eq!(over.len(), limits::MAX_SD_INPUT_BYTES + 1);
    assert_eq!(
        parse(&over, InputSource::MicroSd).err().unwrap().category,
        RejectCategory::InputTooLarge
    );
    // QR boundary.
    let pad_qr = limits::MAX_QR_INPUT_BYTES - base.len() - 4;
    let exact_qr = build(&[rec(0xf0, &[], &vec![0u8; pad_qr])], &[vec![]], &[vec![]]);
    assert_eq!(exact_qr.len(), limits::MAX_QR_INPUT_BYTES);
    assert!(parse(&exact_qr, InputSource::Qr).is_ok());
}

// --- CompactSize boundaries ----------------------------------------------

#[test]
fn compact_size_minimality_is_enforced_at_every_width() {
    // Non-minimal value length: 252 encoded with 0xfd.
    let mut r = vec![0x01, 0xf0, 0xfd, 0xfc, 0x00];
    r.extend_from_slice(&[0u8; 252]);
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::NonMinimalCompactSize
    );
    // Minimal 253 accepted.
    let mut r = vec![0x01, 0xf0, 0xfd, 0xfd, 0x00];
    r.extend_from_slice(&[0u8; 253]);
    assert!(p(&build(&[r], &[vec![]], &[vec![]])).is_ok());
    // Non-minimal 65535 encoded with 0xfe.
    let mut r = vec![0x01, 0xf0, 0xfe, 0xff, 0xff, 0x00, 0x00];
    r.extend_from_slice(&[0u8; 65535]);
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::NonMinimalCompactSize
    );
    // Minimal 65536 accepted.
    let mut r = vec![0x01, 0xf0, 0xfe, 0x00, 0x00, 0x01, 0x00];
    r.extend_from_slice(&[0u8; 65536]);
    assert!(p(&build(&[r], &[vec![]], &[vec![]])).is_ok());
    // Non-minimal 0xffffffff encoded with 0xff (minimality checked
    // before any bounds work).
    let r = vec![
        0x01, 0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::NonMinimalCompactSize
    );
    // Minimal 2^32 value length: truncated (cannot fit any buffer here).
    let r = vec![
        0x01, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::Truncated
    );
    // Non-minimal key length.
    let r = vec![0xfd, 0x01, 0x00, 0xf0, 0x00];
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::NonMinimalCompactSize
    );
    // Non-minimal CompactSize inside the unsigned tx (input count).
    let mut t = vec![2, 0, 0, 0, 0xfd, 0x01, 0x00];
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&[0u8; 4]);
    t.push(0);
    t.extend_from_slice(&[0xff; 4]);
    t.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x51, 0, 0, 0, 0]);
    let mut b = b"psbt\xff".to_vec();
    b.extend_from_slice(&rec(0x00, &[], &t));
    b.push(0);
    b.push(0); // one input map
    b.push(0); // one output map
    assert_eq!(cat(&b), RejectCategory::NonMinimalCompactSize);
}

#[test]
fn key_type_compact_size_inside_key_is_validated() {
    // Non-minimal key type inside a 3-byte key.
    let r = rec_raw(&[0xfd, 0x10, 0x00], &[]);
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::NonMinimalCompactSize
    );
    // Key type CompactSize overruns the key bytes.
    let r = rec_raw(&[0xfd], &[]);
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::InvalidKeyStructure
    );
    let r = rec_raw(&[0xfd, 0x2c], &[]);
    assert_eq!(
        cat(&build(&[r], &[vec![]], &[vec![]])),
        RejectCategory::InvalidKeyStructure
    );
    // Minimal multi-byte key type is preserved as an unknown record.
    let b = build(&[rec(300, &[7, 8], &[9])], &[vec![]], &[vec![]]);
    let v = p(&b).unwrap();
    let recs: Vec<_> = v.global_records().collect();
    assert_eq!(recs[1].key_type, 300);
    assert_eq!(recs[1].key_data, &[7, 8]);
    // Nine-byte minimal key type at the u64 maximum.
    let b = build(&[rec(u64::MAX, &[], &[])], &[vec![]], &[vec![]]);
    let v = p(&b).unwrap();
    assert_eq!(v.global_records().last().unwrap().key_type, u64::MAX);
}

// --- scope-specific policy -----------------------------------------------

#[test]
fn v2_global_fields_reject_and_v0_legal_globals_preserve() {
    for t in 0x02..=0x06u64 {
        let b = build(&[rec(t, &[], &[0])], &[vec![]], &[vec![]]);
        assert_eq!(cat(&b), RejectCategory::V2GlobalField, "type {t:#x}");
    }
    // 0xfb (version, registered for v0) and 0xfc (proprietary) preserve.
    let b = build(
        &[rec(0xfb, &[], &[0, 0, 0, 0]), rec(0xfc, &[9], &[1])],
        &[vec![]],
        &[vec![]],
    );
    assert!(p(&b).is_ok());
}

#[test]
fn taproot_fields_reject_in_their_scopes() {
    for t in 0x13..=0x18u64 {
        let b = build(&[], &[vec![rec(t, &[], &[0])]], &[vec![]]);
        assert_eq!(cat(&b), RejectCategory::TaprootField, "input {t:#x}");
    }
    for t in 0x05..=0x07u64 {
        let b = build(&[], &[vec![]], &[vec![rec(t, &[], &[0])]]);
        assert_eq!(cat(&b), RejectCategory::TaprootField, "output {t:#x}");
    }
}

#[test]
fn bip370_input_output_numbers_are_opaque_preserved_unknowns() {
    for t in 0x0e..=0x12u64 {
        let b = build(&[], &[vec![rec(t, &[1], &[2, 3])]], &[vec![]]);
        assert!(p(&b).is_ok(), "input {t:#x} must preserve");
    }
    for t in [0x03u64, 0x04] {
        let b = build(&[], &[vec![]], &[vec![rec(t, &[1], &[2, 3])]]);
        assert!(p(&b).is_ok(), "output {t:#x} must preserve");
    }
}

// --- duplicate complete raw keys -------------------------------------------

#[test]
fn duplicate_complete_raw_keys_reject_within_one_map_only() {
    let r = rec(0xf0, &[1, 2], &[3]);
    let b = build(&[], &[vec![r.clone(), r.clone()]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::DuplicateKey);
    // Same complete key in two different maps is allowed.
    let b = build(&[], &[vec![r.clone()], vec![r.clone()]], &[vec![]]);
    assert!(p(&b).is_ok());
    // Same type with different key data is not a duplicate.
    let b = build(
        &[],
        &[vec![rec(0xf0, &[1], &[0]), rec(0xf0, &[2], &[0])]],
        &[vec![]],
    );
    assert!(p(&b).is_ok());
    // Duplicate value bytes with identical keys still reject on the key.
    let b = build(
        &[rec(0xf1, &[], &[7]), rec(0xf1, &[], &[8])],
        &[vec![]],
        &[vec![]],
    );
    assert_eq!(cat(&b), RejectCategory::DuplicateKey);
}

// --- limit violations -------------------------------------------------------

#[test]
fn input_output_count_caps_enforced() {
    let inputs: Vec<Vec<Vec<u8>>> = vec![vec![]; limits::MAX_INPUTS];
    let outputs: Vec<Vec<Vec<u8>>> = vec![vec![]; limits::MAX_OUTPUTS];
    assert!(p(&build(&[], &inputs, &outputs)).is_ok());
    let inputs: Vec<Vec<Vec<u8>>> = vec![vec![]; limits::MAX_INPUTS + 1];
    assert_eq!(
        cat(&build(&[], &inputs, &[vec![]])),
        RejectCategory::TooManyInputs
    );
    let outputs: Vec<Vec<Vec<u8>>> = vec![vec![]; limits::MAX_OUTPUTS + 1];
    assert_eq!(
        cat(&build(&[], &[vec![]], &outputs)),
        RejectCategory::TooManyOutputs
    );
}

#[test]
fn signer_record_caps_enforced_per_map() {
    let sigs =
        |n: usize| -> Vec<Vec<u8>> { (0..n).map(|i| rec(0x02, &pubkey(i as u8), &[1])).collect() };
    assert!(p(&build(&[], &[sigs(limits::MAX_SIGNERS)], &[vec![]])).is_ok());
    assert_eq!(
        cat(&build(&[], &[sigs(limits::MAX_SIGNERS + 1)], &[vec![]])),
        RejectCategory::TooManySigners
    );
    let derivs = |n: usize| -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| rec(0x06, &pubkey(i as u8), &bip32_value(1)))
            .collect()
    };
    assert_eq!(
        cat(&build(&[], &[derivs(limits::MAX_SIGNERS + 1)], &[vec![]])),
        RejectCategory::TooManySigners
    );
    // The cap is per map: 15 in each of two maps is fine.
    let b = build(
        &[],
        &[derivs(limits::MAX_SIGNERS), derivs(limits::MAX_SIGNERS)],
        &[vec![]],
    );
    assert!(p(&b).is_ok());
    // The cap is shared across signer-bearing record classes within one
    // map: 8 partial signatures plus 8 derivations (16 total) reject,
    // while 8 plus 7 (15 total) accept.
    let mixed = |n_sigs: usize, n_derivs: usize| -> Vec<Vec<u8>> {
        let mut m: Vec<Vec<u8>> = (0..n_sigs)
            .map(|i| rec(0x02, &pubkey(i as u8), &[1]))
            .collect();
        m.extend((0..n_derivs).map(|i| rec(0x06, &pubkey(0x40 + i as u8), &bip32_value(1))));
        m
    };
    assert_eq!(
        cat(&build(&[], &[mixed(8, 8)], &[vec![]])),
        RejectCategory::TooManySigners
    );
    assert!(p(&build(&[], &[mixed(8, 7)], &[vec![]])).is_ok());
    let out_derivs: Vec<Vec<u8>> = (0..limits::MAX_SIGNERS + 1)
        .map(|i| rec(0x02, &pubkey(i as u8), &bip32_value(1)))
        .collect();
    assert_eq!(
        cat(&build(&[], &[vec![]], &[out_derivs])),
        RejectCategory::TooManySigners
    );
    let xpubs: Vec<Vec<u8>> = (0..limits::MAX_SIGNERS + 1)
        .map(|i| rec(0x01, &[i as u8; 78], &bip32_value(1)))
        .collect();
    assert_eq!(
        cat(&build(&xpubs, &[vec![]], &[vec![]])),
        RejectCategory::TooManySigners
    );
}

#[test]
fn derivation_depth_cap_enforced() {
    let ok = rec(0x06, &pubkey(1), &bip32_value(limits::MAX_PATH_DEPTH));
    assert!(p(&build(&[], &[vec![ok]], &[vec![]])).is_ok());
    let deep = rec(0x06, &pubkey(1), &bip32_value(limits::MAX_PATH_DEPTH + 1));
    assert_eq!(
        cat(&build(&[], &[vec![deep]], &[vec![]])),
        RejectCategory::PathTooDeep
    );
    let deep_out = rec(0x02, &pubkey(1), &bip32_value(limits::MAX_PATH_DEPTH + 1));
    assert_eq!(
        cat(&build(&[], &[vec![]], &[vec![deep_out]])),
        RejectCategory::PathTooDeep
    );
    let deep_xpub = rec(0x01, &[7; 78], &bip32_value(limits::MAX_PATH_DEPTH + 1));
    assert_eq!(
        cat(&build(&[deep_xpub], &[vec![]], &[vec![]])),
        RejectCategory::PathTooDeep
    );
}

// --- key/value structure -----------------------------------------------------

#[test]
fn key_and_value_structure_rules_enforced() {
    // Key data where none is allowed: input utxo/sighash/script/final
    // types and output script types.
    for t in [0x00u64, 0x03, 0x04, 0x05, 0x07, 0x08] {
        let b = build(&[], &[vec![rec(t, &[0xaa], &[0, 0, 0, 0])]], &[vec![]]);
        assert_eq!(cat(&b), RejectCategory::InvalidKeyStructure, "in {t:#x}");
    }
    for t in [0x00u64, 0x01] {
        let b = build(&[], &[vec![]], &[vec![rec(t, &[0xaa], &[0])]]);
        assert_eq!(cat(&b), RejectCategory::InvalidKeyStructure, "out {t:#x}");
    }
    // Wrong pubkey length in partial signature key.
    let b = build(&[], &[vec![rec(0x02, &[0x02; 34], &[1])]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::InvalidKeyStructure);
    // 65-byte pubkey is fine.
    let b = build(&[], &[vec![rec(0x02, &[0x04; 65], &[1])]], &[vec![]]);
    assert!(p(&b).is_ok());
    // Empty partial-signature value.
    let b = build(&[], &[vec![rec(0x02, &pubkey(1), &[])]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::InvalidValueStructure);
    // Sighash value must be exactly four bytes.
    let b = build(&[], &[vec![rec(0x03, &[], &[1, 0, 0])]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::InvalidValueStructure);
    let b = build(&[], &[vec![rec(0x03, &[], &[1, 0, 0, 0])]], &[vec![]]);
    assert!(p(&b).is_ok());
    // BIP32 derivation value shorter than a fingerprint or ragged.
    let b = build(&[], &[vec![rec(0x06, &pubkey(1), &[1, 2, 3])]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::InvalidValueStructure);
    let b = build(
        &[],
        &[vec![rec(0x06, &pubkey(1), &[1, 2, 3, 4, 5])]],
        &[vec![]],
    );
    assert_eq!(cat(&b), RejectCategory::InvalidValueStructure);
    // Global xpub key data must be 78 bytes.
    let b = build(
        &[rec(0x01, &[1; 77], &bip32_value(1))],
        &[vec![]],
        &[vec![]],
    );
    assert_eq!(cat(&b), RejectCategory::InvalidKeyStructure);
    // Witness UTXO value structure: exact consumption required.
    let good = {
        let mut v = vec![0u8; 8];
        v.extend_from_slice(&[2, 0x51, 0x51]);
        v
    };
    let b = build(&[], &[vec![rec(0x01, &[], &good)]], &[vec![]]);
    assert!(p(&b).is_ok());
    let mut trailing = good.clone();
    trailing.push(0);
    let b = build(&[], &[vec![rec(0x01, &[], &trailing)]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::InvalidValueStructure);
    let short = vec![0u8; 7];
    let b = build(&[], &[vec![rec(0x01, &[], &short)]], &[vec![]]);
    assert_eq!(cat(&b), RejectCategory::InvalidValueStructure);
}

// --- unsigned transaction structure ------------------------------------------

fn psbt_with_tx(t: &[u8], n_input_maps: usize, n_output_maps: usize) -> Vec<u8> {
    let mut b = b"psbt\xff".to_vec();
    b.extend_from_slice(&rec(0x00, &[], t));
    b.push(0);
    b.extend_from_slice(&vec![0u8; n_input_maps]);
    b.extend_from_slice(&vec![0u8; n_output_maps]);
    b
}

#[test]
fn malformed_unsigned_transactions_reject_with_exact_categories() {
    // Missing unsigned tx entirely.
    let mut b = b"psbt\xff".to_vec();
    b.push(0);
    assert_eq!(cat(&b), RejectCategory::MissingUnsignedTx);
    // Unsigned tx key with key data.
    let mut b = b"psbt\xff".to_vec();
    b.extend_from_slice(&rec_raw(&[0x00, 0xaa], &tx(1, 1)));
    b.push(0);
    b.push(0);
    b.push(0);
    assert_eq!(cat(&b), RejectCategory::InvalidKeyStructure);
    // Non-empty scriptSig.
    let mut t = vec![2, 0, 0, 0, 1];
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&[0u8; 4]);
    t.extend_from_slice(&[1, 0x51]); // scriptSig length 1
    t.extend_from_slice(&[0xff; 4]);
    t.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x51, 0, 0, 0, 0]);
    assert_eq!(
        cat(&psbt_with_tx(&t, 1, 1)),
        RejectCategory::UnsignedTxScriptSigNotEmpty
    );
    // Witness serialization marker.
    let t = vec![2, 0, 0, 0, 0x00, 0x01, 0x01];
    assert_eq!(
        cat(&psbt_with_tx(&t, 0, 0)),
        RejectCategory::UnsignedTxWitnessFormat
    );
    // Zero inputs (not followed by the witness flag byte).
    let t = vec![2, 0, 0, 0, 0x00, 0x02];
    assert_eq!(
        cat(&psbt_with_tx(&t, 0, 0)),
        RejectCategory::UnsignedTxZeroInputs
    );
    let t = vec![2, 0, 0, 0, 0x00];
    assert_eq!(
        cat(&psbt_with_tx(&t, 0, 0)),
        RejectCategory::UnsignedTxZeroInputs
    );
    // Zero outputs.
    let mut t = vec![2, 0, 0, 0, 1];
    t.extend_from_slice(&[0u8; 32]);
    t.extend_from_slice(&[0u8; 4]);
    t.push(0);
    t.extend_from_slice(&[0xff; 4]);
    t.push(0); // zero outputs
    t.extend_from_slice(&[0; 4]);
    assert_eq!(
        cat(&psbt_with_tx(&t, 1, 0)),
        RejectCategory::UnsignedTxZeroOutputs
    );
    // Trailing byte inside the unsigned tx value.
    let mut t = tx(1, 1);
    t.push(0);
    assert_eq!(
        cat(&psbt_with_tx(&t, 1, 1)),
        RejectCategory::MalformedUnsignedTx
    );
    // Truncated unsigned tx value.
    let full = tx(1, 1);
    let t = &full[..full.len() - 1];
    assert_eq!(
        cat(&psbt_with_tx(t, 1, 1)),
        RejectCategory::MalformedUnsignedTx
    );
}

// --- map counts and trailing bytes --------------------------------------------

#[test]
fn map_count_mismatches_reject() {
    // Two declared inputs, only one input map present.
    let t = tx(2, 1);
    let mut b = b"psbt\xff".to_vec();
    b.extend_from_slice(&rec(0x00, &[], &t));
    b.push(0);
    b.push(0); // one input map only
    assert_eq!(cat(&b), RejectCategory::InvalidMapCount);
    // Declared maps present but output map missing.
    let mut b2 = b.clone();
    b2.push(0); // second input map
    assert_eq!(cat(&b2), RejectCategory::InvalidMapCount);
    // One extra byte after the final map.
    let mut b3 = minimal();
    b3.push(0);
    assert_eq!(cat(&b3), RejectCategory::TrailingBytes);
    // A whole extra map after the final map.
    let mut b4 = minimal();
    b4.extend_from_slice(&rec(0xf0, &[], &[]));
    b4.push(0);
    assert_eq!(cat(&b4), RejectCategory::TrailingBytes);
}

// --- truncation at every byte boundary -----------------------------------------

#[test]
fn every_strict_prefix_rejects_without_panic() {
    let rich = build(
        &[
            rec(0x01, &[3; 78], &bip32_value(2)),
            rec(0xf0, &[1, 2], &[3, 4, 5]),
            rec(0xfc, &[4, b'q', b'k', b'2', 1], &[6]),
        ],
        &[vec![
            rec(0x02, &pubkey(1), &[0x30, 1, 2]),
            rec(0x06, &pubkey(2), &bip32_value(3)),
            rec(0x0e, &[9], &[8, 7]),
        ]],
        &[vec![rec(0x02, &pubkey(3), &bip32_value(1))]],
    );
    assert!(p(&rich).is_ok());
    for l in 0..rich.len() {
        let r = p(&rich[..l]);
        assert!(r.is_err(), "prefix of length {l} must reject");
    }
}

// --- verbatim preservation -------------------------------------------------------

#[test]
fn unknown_and_proprietary_records_preserved_byte_exact_in_order() {
    let unk = rec(0xf0, &[1, 2], &[9, 9, 9]);
    let prop = rec(0xfc, &[4, b'q', b'k', b'2', 0, 7], &[0xde, 0xad]);
    let in_unk = rec(0x11, &[5], &[6, 6]);
    let b = build(
        &[unk.clone(), prop.clone()],
        &[vec![in_unk.clone()]],
        &[vec![]],
    );
    let v = p(&b).unwrap();
    let g: Vec<_> = v.global_records().collect();
    assert_eq!(g.len(), 3);
    assert_eq!(g[1].key_type, 0xf0);
    assert_eq!(g[1].key_data, &[1, 2]);
    assert_eq!(g[1].value, &[9, 9, 9]);
    assert_eq!(g[2].key_type, 0xfc);
    assert_eq!(g[2].key_data, &[4, b'q', b'k', b'2', 0, 7]);
    assert_eq!(g[2].value, &[0xde, 0xad]);
    // Spans resolve to the same bytes as the borrowed slices.
    for r in &g {
        assert_eq!(r.full_key_span.slice(&b).unwrap(), r.full_key);
        assert_eq!(r.value_span.slice(&b).unwrap(), r.value);
        assert_eq!(r.key_data_span.slice(&b).unwrap(), r.key_data);
    }
    // Concatenating raw record bytes reproduces the on-wire map region.
    let i: Vec<_> = v.input_records(0).unwrap().collect();
    assert_eq!(i.len(), 1);
    assert_eq!(i[0].key_type, 0x11);
    let span = v.input_map_span(0).unwrap();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&cs(i[0].full_key.len() as u64));
    rebuilt.extend_from_slice(i[0].full_key);
    rebuilt.extend_from_slice(&cs(i[0].value.len() as u64));
    rebuilt.extend_from_slice(i[0].value);
    rebuilt.push(0);
    assert_eq!(span.slice(&b).unwrap(), &rebuilt[..]);
}

// --- determinism -------------------------------------------------------------------

#[test]
fn parsing_is_deterministic_for_accept_and_reject() {
    let b = build(
        &[rec(0xf0, &[1], &[2])],
        &[vec![rec(0x02, &pubkey(1), &[1])]],
        &[vec![]],
    );
    let v1 = p(&b).unwrap();
    let v2 = p(&b).unwrap();
    assert_eq!(v1.global_map_span(), v2.global_map_span());
    assert_eq!(v1.unsigned_tx(), v2.unsigned_tx());
    let r1: Vec<_> = v1.input_records(0).unwrap().map(|r| r.key_type).collect();
    let r2: Vec<_> = v2.input_records(0).unwrap().map(|r| r.key_type).collect();
    assert_eq!(r1, r2);
    let bad = &b[..b.len() - 1];
    assert_eq!(p(bad).err().unwrap(), p(bad).err().unwrap());
}
