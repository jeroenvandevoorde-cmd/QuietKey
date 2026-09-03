#![allow(clippy::panic, clippy::unwrap_used)]

use qk_card_protocol::{
    parse_record, Profile, RecordError, RECORD_A2_OFFSET, RECORD_BYTES, RECORD_CHANGE_D_OFFSET,
    RECORD_INSTANCE_ID_OFFSET, RECORD_ORIGIN_FINGERPRINT_OFFSET, RECORD_RECEIVE_D_OFFSET,
    RECORD_WALLET_ID_OFFSET, RECORD_XPRV_OFFSET,
};

const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn valid_record() -> [u8; RECORD_BYTES] {
    let mut record = [0u8; RECORD_BYTES];
    record[0..4].copy_from_slice(b"QKCB");
    record[4] = 1;
    record[5] = Profile::QuantumShelter.byte();
    record[6] = 2;
    record[RECORD_INSTANCE_ID_OFFSET..RECORD_WALLET_ID_OFFSET].fill(0x11);
    record[RECORD_WALLET_ID_OFFSET..RECORD_ORIGIN_FINGERPRINT_OFFSET].fill(0x22);
    record[RECORD_ORIGIN_FINGERPRINT_OFFSET..RECORD_XPRV_OFFSET].fill(0x33);
    record[59..63].copy_from_slice(&[0x04, 0x88, 0xad, 0xe4]);
    record[63] = 4;
    record[64..68].fill(0x33);
    record[68..72].copy_from_slice(&[0x80, 0, 0, 2]);
    record[72..104].fill(0x44);
    record[104] = 0;
    record[105..137].fill(0);
    record[136] = 1;
    record[RECORD_A2_OFFSET..RECORD_RECEIVE_D_OFFSET].fill(0x55);
    record[RECORD_RECEIVE_D_OFFSET..RECORD_CHANGE_D_OFFSET].fill(0x66);
    record[RECORD_CHANGE_D_OFFSET..RECORD_BYTES].fill(0x77);
    record
}

#[test]
fn offsets_and_getters_are_byte_exact() {
    let record = valid_record();
    let parsed = parse_record(&record).unwrap();
    assert_eq!(parsed.profile(), Profile::QuantumShelter);
    assert_eq!(parsed.instance_id(), &[0x11; 16]);
    assert_eq!(parsed.wallet_id(), &[0x22; 32]);
    assert_eq!(parsed.origin_fingerprint(), &[0x33; 4]);
    assert_eq!(parsed.account_xprv().parent_fingerprint(), &[0x33; 4]);
    assert_eq!(parsed.account_xprv().chain_code(), &[0x44; 32]);
    assert_eq!(parsed.account_xprv().scalar()[31], 1);
    assert_eq!(parsed.a2(), &[0x55; 32]);
    assert_eq!(parsed.receive_descriptor(), &[0x66; 306]);
    assert_eq!(parsed.change_descriptor(), &[0x77; 306]);
    assert_eq!(parsed.bytes(), &record);
}

#[test]
fn scalar_zero_n_minus_one_and_n_are_locked() {
    let mut record = valid_record();
    record[105..137].fill(0);
    assert_eq!(parse_record(&record), Err(RecordError::XprvScalar));

    let mut n_minus_one = N;
    n_minus_one[31] -= 1;
    record[105..137].copy_from_slice(&n_minus_one);
    assert!(parse_record(&record).is_ok());

    record[105..137].copy_from_slice(&N);
    assert_eq!(parse_record(&record), Err(RecordError::XprvScalar));
}

#[test]
fn every_structural_field_has_a_named_rejection() {
    let cases: &[(usize, u8, RecordError)] = &[
        (0, b'X', RecordError::Magic),
        (4, 2, RecordError::Version),
        (5, 4, RecordError::Profile),
        (6, 1, RecordError::Role),
        (59, 5, RecordError::XprvVersion),
        (63, 3, RecordError::XprvDepth),
        (68, 0, RecordError::XprvChildNumber),
        (104, 1, RecordError::XprvKeyPrefix),
    ];
    for (offset, value, expected) in cases {
        let mut record = valid_record();
        record[*offset] = *value;
        assert_eq!(parse_record(&record), Err(*expected));
        assert!(!expected.name().is_empty());
    }
    assert_eq!(
        parse_record(&valid_record()[..780]),
        Err(RecordError::Length)
    );
}
