//! CKDpriv and deterministic public-test signing coverage.

use qk_card_model::{CardModel, ModelMode, ModelProfile, RECORD_BYTES};

const NEVER_FUND_NOTICE: &str = "PERMANENTLY NEVER-FUND TEST MATERIAL";
const FIXTURE: &str = include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
const NONCE: [u8; 12] = *b"QKV2S4NONCE1";
const SETUP_ID: [u8; 16] = [0x64; 16];
const NORMAL_ID: [u8; 16] = [0x65; 16];

fn fixture_record(profile: ModelProfile) -> [u8; RECORD_BYTES] {
    let prefix = match profile {
        ModelProfile::SimpleRecovery => "record_profile_01_hex: ",
        ModelProfile::Inheritance => "record_profile_02_hex: ",
        ModelProfile::QuantumShelter => "record_profile_03_hex: ",
    };
    let value = FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .expect("registered record");
    let mut record = [0u8; RECORD_BYTES];
    assert_eq!(value.len(), record.len() * 2);
    for (output, pair) in record.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *output = u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
            .expect("fixture hex");
    }
    record
}

fn fixture_hex(name: &str) -> Vec<u8> {
    let prefix = format!("{name}: ");
    let value = FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("registered fact");
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

fn committed() -> (CardModel, [u8; 781]) {
    assert!(FIXTURE.contains(NEVER_FUND_NOTICE));
    let record = fixture_record(ModelProfile::Inheritance);
    let mut model = CardModel::new();
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    model
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    for (sequence, (offset, length)) in [
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
                &SETUP_ID,
                2 + sequence as u32,
                offset as u16,
                &record[offset..offset + length],
            )
            .expect("write");
    }
    model.commit(&SETUP_ID, 7).expect("commit");
    (model, record)
}

#[test]
fn signatures_are_bound_ordered_low_s_and_self_verifying() {
    let (mut model, record) = committed();
    model.select(true).expect("select");
    model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&record[23..55]);
    let review = [0x72; 32];
    let first_digest = [0x81; 32];
    let first = model
        .sign_digest(&NORMAL_ID, 1, &wallet, &review, 2, 0, 0, &first_digest)
        .expect("first sign");
    let key = qk_secp::pubkey_parse_compressed(first.public_key()).expect("public key");
    let signature = qk_secp::signature_parse_der(first.der()).expect("strict DER");
    qk_secp::ecdsa_verify(&signature, &first_digest, &key).expect("verified signature");
    assert!(
        first.der().len() <= 71,
        "model fixture signer emits normalized low-S DER"
    );

    let second = model
        .sign_digest(&NORMAL_ID, 2, &wallet, &review, 9, 1, 65_535, &[0x82; 32])
        .expect("second sign");
    assert_eq!(second.input_index(), 9);
    assert_eq!(second.review_hash(), &review);
    drop(second);
    assert_eq!(
        model
            .sign_digest(&NORMAL_ID, 3, &wallet, &review, 8, 0, 0, &[0x83; 32])
            .map(|_| ()),
        Err(qk_card_model::ModelError::SigningBindingRejected)
    );
}

#[test]
fn same_public_fixture_inputs_produce_byte_identical_signatures() {
    fn once() -> (Vec<u8>, [u8; 33]) {
        let (mut model, record) = committed();
        model.select(true).expect("select");
        model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
        let mut wallet = [0u8; 32];
        wallet.copy_from_slice(&record[23..55]);
        let reply = model
            .sign_digest(&NORMAL_ID, 1, &wallet, &[0x91; 32], 0, 1, 7, &[0x92; 32])
            .expect("sign");
        (reply.der().to_vec(), *reply.public_key())
    }
    assert_eq!(once(), once());
}

#[test]
fn committed_xpub_is_derived_once_from_the_public_fixture_xprv() {
    let (mut model, record) = committed();
    assert_eq!(&record[7..23], fixture_hex("instance_id_hex"));
    assert_eq!(&record[23..55], fixture_hex("wallet_id_hex"));
    assert_eq!(&record[137..169], fixture_hex("a2_hex"));
    model.select(true).expect("select");
    model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    let info = model.info(&NORMAL_ID, 1).expect("info");
    assert_eq!(
        info.account_xpub.as_slice(),
        fixture_hex("account_xpub_raw_hex")
    );
}

fn der_s(signature: &[u8]) -> [u8; 32] {
    let r_len = usize::from(signature[3]);
    let s_len = usize::from(signature[5 + r_len]);
    let start = 6 + r_len;
    let encoded = &signature[start..start + s_len];
    let magnitude = if encoded[0] == 0 {
        &encoded[1..]
    } else {
        encoded
    };
    let mut value = [0u8; 32];
    value[32 - magnitude.len()..].copy_from_slice(magnitude);
    value
}

#[test]
fn deterministic_high_s_seam_emits_the_valid_sibling() {
    fn once(high: bool) -> (Vec<u8>, [u8; 33]) {
        let (mut model, record) = committed();
        model.select(true).expect("select");
        model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
        if high {
            model.emit_high_s_once();
        }
        let mut wallet = [0u8; 32];
        wallet.copy_from_slice(&record[23..55]);
        let digest = [0xa5; 32];
        let reply = model
            .sign_digest(&NORMAL_ID, 1, &wallet, &[0xa4; 32], 4, 1, 65_535, &digest)
            .expect("sign");
        let key = qk_secp::pubkey_parse_compressed(reply.public_key()).expect("public key");
        let signature = qk_secp::signature_parse_der(reply.der()).expect("strict DER");
        if high {
            assert_eq!(
                qk_secp::ecdsa_verify(&signature, &digest, &key),
                Err(qk_secp::SecpError::VerificationFailed)
            );
            let mut normalized = [0u8; 72];
            let normalized_len =
                qk_secp::normalize_card_signature_der(reply.der(), &mut normalized)
                    .expect("normalize high-S sibling");
            let normalized_signature = qk_secp::signature_parse_der(&normalized[..normalized_len])
                .expect("normalized DER");
            qk_secp::ecdsa_verify(&normalized_signature, &digest, &key)
                .expect("normalized sibling verifies");
        } else {
            qk_secp::ecdsa_verify(&signature, &digest, &key).expect("low-S verifies");
        }
        (reply.der().to_vec(), *reply.public_key())
    }
    let (low, low_key) = once(false);
    let (high, high_key) = once(true);
    assert_eq!(low_key, high_key);
    assert_ne!(low, high);
    let half_order = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    assert!(der_s(&low) <= half_order);
    assert!(der_s(&high) > half_order);
    let mut normalized = [0xa5u8; 72];
    let normalized_len =
        qk_secp::normalize_card_signature_der(&high, &mut normalized).expect("normalize sibling");
    assert_eq!(&normalized[..normalized_len], low.as_slice());
    assert!(normalized[normalized_len..].iter().all(|byte| *byte == 0));
}

#[test]
fn signing_precedence_caps_and_fault_seams_are_exact() {
    let (mut model, record) = committed();
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&record[23..55]);
    model.select(true).expect("select");
    model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    let mut wrong_wallet = wallet;
    wrong_wallet[0] ^= 1;
    assert_eq!(
        model
            .sign_digest(
                &NORMAL_ID,
                1,
                &wrong_wallet,
                &[1; 32],
                0,
                2,
                70_000,
                &[2; 32]
            )
            .map(|_| ()),
        Err(qk_card_model::ModelError::WalletBindingRejected)
    );

    for (fault, expected) in [
        (
            qk_card_model::FaultPoint::ChildDerivation,
            qk_card_model::ModelError::ChildDerivationRejected,
        ),
        (
            qk_card_model::FaultPoint::CryptographicOperation,
            qk_card_model::ModelError::CryptographicOperationRejected,
        ),
    ] {
        let (mut faulted, _) = committed();
        faulted.select(true).expect("select");
        faulted.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
        faulted.inject_fault(fault);
        assert_eq!(
            faulted
                .sign_digest(&NORMAL_ID, 1, &wallet, &[3; 32], 0, 0, 0, &[4; 32])
                .map(|_| ()),
            Err(expected)
        );
    }

    let (mut capped, _) = committed();
    capped.select(true).expect("select");
    capped.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    for index in 0..100u32 {
        capped
            .sign_digest(
                &NORMAL_ID,
                index + 1,
                &wallet,
                &[5; 32],
                index,
                0,
                0,
                &[6; 32],
            )
            .expect("within sign cap");
    }
    assert_eq!(
        capped
            .sign_digest(&NORMAL_ID, 101, &wallet, &[5; 32], 100, 0, 0, &[6; 32])
            .map(|_| ()),
        Err(qk_card_model::ModelError::ModeOrOperationRejected)
    );
}

#[test]
fn child_derivation_rejection_precedes_changed_session_binding() {
    let (mut model, record) = committed();
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&record[23..55]);
    model.select(true).expect("select");
    model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    model
        .sign_digest(&NORMAL_ID, 1, &wallet, &[0xb1; 32], 4, 0, 0, &[0xb2; 32])
        .expect("first sign");
    model.inject_fault(qk_card_model::FaultPoint::ChildDerivation);
    assert_eq!(
        model
            .sign_digest(&NORMAL_ID, 2, &wallet, &[0xb3; 32], 3, 0, 0, &[0xb4; 32])
            .map(|_| ()),
        Err(qk_card_model::ModelError::ChildDerivationRejected)
    );
}
