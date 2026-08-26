#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair, DescriptorParseError};

const DESCRIPTOR_LEN: usize = 445;
const BODY_LEN: usize = 436;
const BRANCH_POSITIONS: [usize; 3] = [153, 292, 431];
const PREFIX: &[u8] = b"wsh(sortedmulti(2,";
static OVERSIZE_SIDE: [u8; DESCRIPTOR_LEN + 1] = [0; DESCRIPTOR_LEN + 1];
const PUBLIC_PAIR_FIXTURE: &[u8] =
    include_bytes!("../../host/qk-descriptor/tests/fixtures/descriptor_pairs.txt");

fn reject_name(error: DescriptorParseError) -> &'static str {
    match error {
        DescriptorParseError::InvalidDescriptorLength => "InvalidDescriptorLength",
        DescriptorParseError::InvalidChecksumDelimiter => "InvalidChecksumDelimiter",
        DescriptorParseError::InvalidChecksumCharacter => "InvalidChecksumCharacter",
        DescriptorParseError::InvalidDescriptorCharacter => "InvalidDescriptorCharacter",
        DescriptorParseError::ChecksumMismatch => "ChecksumMismatch",
        DescriptorParseError::NonCanonicalDescriptor => "NonCanonicalDescriptor",
        DescriptorParseError::DescriptorPairMismatch => "DescriptorPairMismatch",
        DescriptorParseError::InvalidAccountXpub => "InvalidAccountXpub",
        DescriptorParseError::InvalidAccountDepth => "InvalidAccountDepth",
        DescriptorParseError::InvalidAccountChildNumber => "InvalidAccountChildNumber",
        DescriptorParseError::DuplicateAccountXpub => "DuplicateAccountXpub",
        DescriptorParseError::CryptographicBackendInvariant => "CryptographicBackendInvariant",
    }
}

fn assert_canonical_pair(receive: &[u8], change: &[u8]) {
    assert_eq!(receive.len(), DESCRIPTOR_LEN);
    assert_eq!(change.len(), DESCRIPTOR_LEN);
    assert_eq!(&receive[..PREFIX.len()], PREFIX);
    assert_eq!(&change[..PREFIX.len()], PREFIX);
    assert_eq!(receive[BODY_LEN], b'#');
    assert_eq!(change[BODY_LEN], b'#');

    for index in 0..BODY_LEN {
        if BRANCH_POSITIONS.contains(&index) {
            assert_eq!(receive[index], b'0');
            assert_eq!(change[index], b'1');
        } else {
            assert_eq!(receive[index], change[index]);
        }
    }
}

fn exercise_pair(receive: &[u8], change: &[u8]) {
    let pair = match parse_descriptor_pair(receive, change) {
        Ok(pair) => pair,
        Err(error) => {
            assert!(!reject_name(error).is_empty());
            match parse_descriptor_pair(receive, change) {
                Err(repeated) => assert_eq!(repeated, error),
                Ok(_) => panic!("rejected descriptor pair accepted on exact replay"),
            }
            return;
        }
    };

    assert_canonical_pair(receive, change);
    let reparsed = match parse_descriptor_pair(receive, change) {
        Ok(pair) => pair,
        Err(error) => {
            let name = reject_name(error);
            panic!("accepted canonical descriptor pair rejected on reparse as {name}");
        }
    };
    assert_eq!(reparsed.wallet_id(), pair.wallet_id());
    assert_eq!(reparsed.origin_fingerprints(), pair.origin_fingerprints());
}

fn exercise_raw(data: &[u8]) {
    let split = data.len().min(DESCRIPTOR_LEN);
    let (receive, change) = data.split_at(split);
    exercise_pair(receive, change);
}

fn exercise_mutated(data: &[u8], golden_receive: &[u8], golden_change: &[u8]) {
    let mut receive = golden_receive.to_vec();
    let mut change = golden_change.to_vec();
    let edit_count = data.len().saturating_sub(1) / 4;
    for edit in 0..edit_count.min(16) {
        let base = 1 + edit * 4;
        let position =
            (usize::from(data[base + 1]) << 8 | usize::from(data[base + 2])) % DESCRIPTOR_LEN;
        let replacement = data[base + 3];
        if data[base] & 1 == 0 {
            receive[position] = replacement;
        } else {
            change[position] = replacement;
        }
    }
    exercise_pair(&receive, &change);
}

fn golden_pair() -> (&'static [u8], &'static [u8]) {
    let mut receive = None;
    let mut change = None;
    for line in PUBLIC_PAIR_FIXTURE.split(|byte| *byte == b'\n') {
        if receive.is_none() {
            receive = line.strip_prefix(b"receive: ");
        } else if change.is_none() {
            change = line.strip_prefix(b"change: ");
        }
        if receive.is_some() && change.is_some() {
            break;
        }
    }
    (
        receive.expect("committed public fixture receive descriptor"),
        change.expect("committed public fixture change descriptor"),
    )
}

fuzz_target!(|data: &[u8]| {
    exercise_raw(data);
    let (receive, change) = golden_pair();
    exercise_pair(receive, change);
    exercise_mutated(data, receive, change);
    exercise_pair(&OVERSIZE_SIDE, change);
    exercise_pair(receive, &OVERSIZE_SIDE);
});
