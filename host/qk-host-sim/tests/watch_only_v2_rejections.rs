//! V2 slice-6 closed construction and reopened-record rejection categories.

#[path = "support/v2_s6.rs"]
mod support;

use qk_host_sim::{
    BsmsErrorV2, WatchOnlyCoordinatorTierV2, WatchOnlyExportArtifactsV2, WatchOnlyExportErrorV2,
    BSMS_RECORD_BYTES_V2,
};
use qk_provisioning::ProvisioningArtifactsV2;
use support::{bsms_bytes, owner, provisioning};

const DESCRIPTOR_START: usize = 9;
const DESCRIPTOR_BODY_BYTES: usize = 305;
const DESCRIPTOR_CHECKSUM_START: usize = DESCRIPTOR_START + DESCRIPTOR_BODY_BYTES + 1;
const DESCRIPTOR_END: usize = DESCRIPTOR_CHECKSUM_START + 8;
const RESTRICTIONS_START: usize = DESCRIPTOR_END + 1;
const ADDRESS_START: usize = RESTRICTIONS_START + 20 + 1;

const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

fn assert_build_error(artifacts: &ProvisioningArtifactsV2, expected: BsmsErrorV2) {
    match WatchOnlyExportArtifactsV2::from_provisioning(
        artifacts,
        WatchOnlyCoordinatorTierV2::SimpleRecovery,
    ) {
        Err(WatchOnlyExportErrorV2::Bsms(actual)) => assert_eq!(actual, expected),
        Err(other) => panic!("unexpected outer error: {other}"),
        Ok(_) => panic!("invalid provisioning facts were accepted"),
    }
}

fn assert_reopen_error(bytes: &[u8], expected: BsmsErrorV2) {
    let owner = owner(WatchOnlyCoordinatorTierV2::SimpleRecovery).expect("valid v2 owner");
    assert_eq!(owner.artifact().verify_reopened(bytes), Err(expected));
}

fn polymod(mut state: u64, value: u8) -> u64 {
    let high = state >> 35;
    state = ((state & 0x7_ffff_ffff) << 5) ^ u64::from(value);
    for (bit, generator) in GENERATORS.iter().enumerate() {
        if ((high >> bit) & 1) != 0 {
            state ^= generator;
        }
    }
    state
}

fn charset_position(byte: u8) -> u8 {
    INPUT_CHARSET
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|position| u8::try_from(position).ok())
        .expect("test mutation remains in BIP380 charset")
}

fn descriptor_checksum(body: &[u8]) -> [u8; 8] {
    let mut state = 1u64;
    let mut class = 0u8;
    let mut class_count = 0u8;
    for &byte in body {
        let position = charset_position(byte);
        state = polymod(state, position & 31);
        class = class * 3 + (position >> 5);
        class_count += 1;
        if class_count == 3 {
            state = polymod(state, class);
            class = 0;
            class_count = 0;
        }
    }
    if class_count != 0 {
        state = polymod(state, class);
    }
    for _ in 0..8 {
        state = polymod(state, 0);
    }
    state ^= 1;
    let mut output = [0u8; 8];
    for (position, slot) in output.iter_mut().enumerate() {
        let symbol = ((state >> (5 * (7 - position))) & 31) as usize;
        *slot = CHECKSUM_CHARSET[symbol];
    }
    output
}

#[test]
fn construction_rejections_and_fact_precedence_are_exact() {
    let mut invalid_pair = provisioning();
    invalid_pair.descriptors[0][305] ^= 1;
    assert_build_error(&invalid_pair, BsmsErrorV2::InvalidDescriptorPair);

    let mut wallet = provisioning();
    wallet.wallet_id[0] ^= 1;
    assert_build_error(&wallet, BsmsErrorV2::WalletIdMismatch);

    let mut script = provisioning();
    script.first_scripts[0][2] ^= 1;
    assert_build_error(&script, BsmsErrorV2::FirstScriptMismatch);

    let mut address = provisioning();
    address.first_addresses[1][3] ^= 1;
    assert_build_error(&address, BsmsErrorV2::FirstAddressMismatch);

    let mut ordered = provisioning();
    ordered.wallet_id[0] ^= 1;
    ordered.first_scripts[0][2] ^= 1;
    ordered.first_addresses[0][3] ^= 1;
    assert_build_error(&ordered, BsmsErrorV2::WalletIdMismatch);

    let mut ordered = provisioning();
    ordered.first_scripts[0][2] ^= 1;
    ordered.first_addresses[0][3] ^= 1;
    assert_build_error(&ordered, BsmsErrorV2::FirstScriptMismatch);
}

#[test]
fn reopened_framing_and_line_rejections_have_exact_precedence() {
    let canonical = bsms_bytes();
    assert_eq!(canonical.len(), BSMS_RECORD_BYTES_V2);

    let mut short_and_non_ascii = canonical[..BSMS_RECORD_BYTES_V2 - 1].to_vec();
    short_and_non_ascii[0] = 0xff;
    assert_reopen_error(&short_and_non_ascii, BsmsErrorV2::InvalidRecordLength);

    let mut non_ascii_version = canonical.clone();
    non_ascii_version[0] = 0xff;
    assert_reopen_error(&non_ascii_version, BsmsErrorV2::InvalidRecordEncoding);

    let mut version_and_descriptor = canonical.clone();
    version_and_descriptor[0] = b'C';
    version_and_descriptor[DESCRIPTOR_CHECKSUM_START] = b'q';
    assert_reopen_error(&version_and_descriptor, BsmsErrorV2::InvalidVersionLine);

    let mut descriptor_and_restrictions = canonical.clone();
    descriptor_and_restrictions[DESCRIPTOR_CHECKSUM_START] = b'q';
    descriptor_and_restrictions[RESTRICTIONS_START] = b'X';
    assert_reopen_error(
        &descriptor_and_restrictions,
        BsmsErrorV2::InvalidDescriptorLine,
    );

    let mut restrictions_and_address = canonical.clone();
    restrictions_and_address[RESTRICTIONS_START] = b'X';
    restrictions_and_address[ADDRESS_START] = b'B';
    assert_reopen_error(
        &restrictions_and_address,
        BsmsErrorV2::InvalidRestrictionsLine,
    );

    let mut address = canonical.clone();
    address[ADDRESS_START] = b'B';
    assert_reopen_error(&address, BsmsErrorV2::InvalidAddressLine);

    let mut malformed_framing = canonical;
    malformed_framing[BSMS_RECORD_BYTES_V2 - 1] = b'!';
    assert_reopen_error(&malformed_framing, BsmsErrorV2::InvalidRecordEncoding);
}

#[test]
fn valid_checksum_foreign_descriptor_is_a_round_trip_mismatch() {
    let mut foreign = bsms_bytes();
    assert_eq!(foreign[DESCRIPTOR_START + 19], b'2');
    foreign[DESCRIPTOR_START + 19] = b'3';
    let checksum =
        descriptor_checksum(&foreign[DESCRIPTOR_START..DESCRIPTOR_START + DESCRIPTOR_BODY_BYTES]);
    foreign[DESCRIPTOR_CHECKSUM_START..DESCRIPTOR_END].copy_from_slice(&checksum);

    assert_ne!(
        &foreign[DESCRIPTOR_CHECKSUM_START..DESCRIPTOR_END],
        &bsms_bytes()[DESCRIPTOR_CHECKSUM_START..DESCRIPTOR_END]
    );
    assert_reopen_error(&foreign, BsmsErrorV2::DescriptorRoundTripMismatch);
}

#[test]
fn every_closed_bsms_error_displays_its_exact_named_category() {
    for (error, name) in [
        (BsmsErrorV2::InvalidDescriptorPair, "InvalidDescriptorPair"),
        (BsmsErrorV2::WalletIdMismatch, "WalletIdMismatch"),
        (BsmsErrorV2::FirstScriptMismatch, "FirstScriptMismatch"),
        (BsmsErrorV2::FirstAddressMismatch, "FirstAddressMismatch"),
        (
            BsmsErrorV2::DescriptorRoundTripMismatch,
            "DescriptorRoundTripMismatch",
        ),
        (BsmsErrorV2::InvalidRecordLength, "InvalidRecordLength"),
        (BsmsErrorV2::InvalidRecordEncoding, "InvalidRecordEncoding"),
        (BsmsErrorV2::InvalidVersionLine, "InvalidVersionLine"),
        (BsmsErrorV2::InvalidDescriptorLine, "InvalidDescriptorLine"),
        (
            BsmsErrorV2::InvalidRestrictionsLine,
            "InvalidRestrictionsLine",
        ),
        (BsmsErrorV2::InvalidAddressLine, "InvalidAddressLine"),
    ] {
        assert_eq!(error.to_string(), name);
    }
}

#[test]
fn v1_record_and_three_key_geometry_have_no_translation_path() {
    let v1 = include_bytes!("fixtures/m28_watch_only.txt");
    let v1_record_hex = v1
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            core::str::from_utf8(line)
                .ok()?
                .strip_prefix("bsms_bytes_hex: ")
        })
        .expect("registered M28 record");
    let v1_record: Vec<u8> = v1_record_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(v1_record.len(), 551);
    assert_reopen_error(&v1_record, BsmsErrorV2::InvalidRecordLength);
}
