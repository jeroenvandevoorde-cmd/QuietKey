//! Model execution against the two-constructor registered GOLDEN transcript.
//!
//! The fixture is PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL. Its header
//! records the public source strings, constructor identities, agreement, and
//! destruction procedure; this test introduces no second fixture authority.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use qk_card_model::{CardModel, ModelMode, ModelProfile, RESPONSE_BYTES};
use qk_card_protocol::{Media, RECORD_BYTES};

const FIXTURE: &str = include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
const FIXTURE_NONCE: [u8; 12] = *b"QKV2S4NONCE1";
const SETUP_SESSION: [u8; 16] = [0xa1; 16];
const NORMAL_SESSION: [u8; 16] = [0xb2; 16];

fn fixture() -> BTreeMap<&'static str, &'static str> {
    let fields: BTreeMap<_, _> = FIXTURE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once(": ").expect("fixture field"))
        .collect();
    assert_eq!(fields.len(), 81);
    fields
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("fixture hex")
        })
        .collect()
}

fn bytes(fields: &BTreeMap<&str, &str>, name: &str) -> Vec<u8> {
    decode_hex(fields.get(name).expect("fixture field"))
}

fn record(fields: &BTreeMap<&str, &str>, profile: ModelProfile) -> [u8; RECORD_BYTES] {
    let name = match profile {
        ModelProfile::SimpleRecovery => "record_profile_01_hex",
        ModelProfile::Inheritance => "record_profile_02_hex",
        ModelProfile::QuantumShelter => "record_profile_03_hex",
    };
    bytes(fields, name)
        .try_into()
        .expect("exact registered record")
}

fn exchange_exact(
    model: &mut CardModel,
    fields: &BTreeMap<&str, &str>,
    request_name: &str,
    response_name: &str,
) {
    let request = bytes(fields, request_name);
    let expected = bytes(fields, response_name);
    let mut response = [0xa5; RESPONSE_BYTES];
    let length = model
        .process_apdu(Media::ContactT1, &request, &mut response)
        .expect("registered APDU succeeds");
    assert_eq!(&response[..length], expected);
    assert!(response[length..].iter().all(|byte| *byte == 0));
}

fn provision_exact(model: &mut CardModel, fields: &BTreeMap<&str, &str>) {
    exchange_exact(
        model,
        fields,
        "setup_select_request_hex",
        "setup_select_response_hex",
    );
    exchange_exact(
        model,
        fields,
        "setup_open_request_hex",
        "setup_open_response_hex",
    );
    exchange_exact(
        model,
        fields,
        "setup_begin_request_hex",
        "setup_begin_response_hex",
    );
    for offset in ["0", "192", "384", "576", "768"] {
        exchange_exact(
            model,
            fields,
            &format!("setup_write_{offset}_request_hex"),
            &format!("setup_write_{offset}_response_hex"),
        );
    }
    exchange_exact(
        model,
        fields,
        "setup_commit_request_hex",
        "setup_commit_response_hex",
    );
}

#[test]
fn complete_setup_and_normal_trace_matches_every_registered_byte() {
    let fields = fixture();
    let mut model = CardModel::new();
    provision_exact(&mut model, &fields);
    for (request, response) in [
        ("normal_select_request_hex", "normal_select_response_hex"),
        ("normal_open_request_hex", "normal_open_response_hex"),
        ("normal_info_request_hex", "normal_info_response_hex"),
        (
            "normal_read_1_0_request_hex",
            "normal_read_1_0_response_hex",
        ),
        (
            "normal_read_1_192_request_hex",
            "normal_read_1_192_response_hex",
        ),
        (
            "normal_read_2_0_request_hex",
            "normal_read_2_0_response_hex",
        ),
        (
            "normal_read_2_192_request_hex",
            "normal_read_2_192_response_hex",
        ),
        ("normal_a2_request_hex", "normal_a2_response_hex"),
        ("normal_sign_0_request_hex", "normal_sign_0_response_hex"),
    ] {
        exchange_exact(&mut model, &fields, request, response);
    }
}

#[test]
fn all_three_registered_records_produce_the_registered_core_facts() {
    let fields = fixture();
    for (profile, profile_byte) in [
        (ModelProfile::SimpleRecovery, 1u8),
        (ModelProfile::Inheritance, 2),
        (ModelProfile::QuantumShelter, 3),
    ] {
        let source = record(&fields, profile);
        let mut model = CardModel::new();
        model.select(true).expect("select");
        model
            .open(1, ModelMode::Setup, SETUP_SESSION)
            .expect("open setup");
        model
            .begin_provision(&SETUP_SESSION, 1, 1, FIXTURE_NONCE)
            .expect("begin");
        for (sequence, (offset, width)) in [
            (0usize, 192usize),
            (192, 192),
            (384, 192),
            (576, 192),
            (768, 13),
        ]
        .iter()
        .copied()
        .enumerate()
        {
            model
                .write_chunk(
                    &SETUP_SESSION,
                    2 + sequence as u32,
                    offset as u16,
                    &source[offset..offset + width],
                )
                .expect("write");
        }
        model.commit(&SETUP_SESSION, 7).expect("commit");
        model.select(true).expect("select normal");
        model
            .open(1, ModelMode::Normal, NORMAL_SESSION)
            .expect("open normal");
        let info = model.info(&NORMAL_SESSION, 1).expect("info");
        assert_eq!(info.profile, profile_byte);
        assert_eq!(info.role, 2);
        assert_eq!(info.allowed_operations, 0x000f);
        assert_eq!(
            info.wallet_id.as_slice(),
            bytes(&fields, "qk_core_bound_wallet_id_hex")
        );
        assert_eq!(
            info.account_xpub.as_slice(),
            bytes(&fields, "account_xpub_raw_hex")
        );
        assert_eq!(
            fields[&*format!("qk_core_profile_{profile_byte:02}_bind_outcome")],
            "BoundNormalCardBDataV2"
        );
    }
}

#[test]
fn registered_normal_signature_is_bound_and_verifies() {
    let fields = fixture();
    let mut model = CardModel::new();
    provision_exact(&mut model, &fields);
    model.select(true).expect("select normal");
    model
        .open(1, ModelMode::Normal, NORMAL_SESSION)
        .expect("open normal");
    let wallet: [u8; 32] = bytes(&fields, "wallet_id_hex")
        .try_into()
        .expect("wallet id");
    let review: [u8; 32] = bytes(&fields, "review_hash_hex")
        .try_into()
        .expect("review hash");
    let digest: [u8; 32] = bytes(&fields, "digest_hex").try_into().expect("digest");
    let reply = model
        .sign_digest(&NORMAL_SESSION, 1, &wallet, &review, 0, 0, 0, &digest)
        .expect("signature");
    assert_eq!(
        reply.public_key().as_slice(),
        bytes(&fields, "qk_core_role_b_public_key_hex").as_slice()
    );
    assert_eq!(
        reply.der(),
        bytes(&fields, "qk_core_role_b_signature_der_hex").as_slice()
    );
    let public_key = qk_secp::pubkey_parse_compressed(reply.public_key()).expect("public key");
    let signature = qk_secp::signature_parse_der(reply.der()).expect("strict DER");
    qk_secp::ecdsa_verify(&signature, &digest, &public_key).expect("signature verifies");
}
