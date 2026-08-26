//! Deterministic M24 signing-boundary fixture and failure checks.

use qk_secp::{
    ecdsa_sign_rfc6979, ecdsa_verify, pubkey_parse_compressed, secret_key_import,
    signature_parse_der, signature_serialize_der, SecpError,
};

#[allow(dead_code)]
#[path = "../../qk-psbt/src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &str = include_str!("fixtures/m24_signing_boundary.txt");
const FIXTURE_BYTES: usize = 6_923;
const FIXTURE_LF: usize = 78;
const FIXTURE_SHA256_HEX: &str = "211ca5531596f83d1c16a189ab57053cb1bad4b184453e10030d82dedc59fda4";
const G_COMPRESSED: [u8; 33] =
    hex_array::<33>("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex fixture digit"),
    }
}

const fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    let bytes = text.as_bytes();
    assert!(bytes.len() == N * 2);
    let mut output = [0u8; N];
    let mut index = 0usize;
    while index < N {
        output[index] = nibble(bytes[index * 2]) * 16 + nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

fn field(name: &str) -> &str {
    let prefix = format!("{name}=");
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0u8; N];
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    for (destination, [high, low]) in output.iter_mut().zip(pairs) {
        *destination = nibble(*high) * 16 + nibble(*low);
    }
    output
}

fn decode_hex_vec(text: &str) -> Vec<u8> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|[high, low]| nibble(*high) * 16 + nibble(*low))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[test]
fn fixture_identity_derivation_and_screening_are_locked() {
    assert_eq!(FIXTURE.len(), FIXTURE_BYTES);
    assert_eq!(
        FIXTURE.bytes().filter(|byte| *byte == b'\n').count(),
        FIXTURE_LF
    );
    assert_eq!(FIXTURE.lines().count(), FIXTURE_LF);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    let digest = fixture_sha256::sha256(&[FIXTURE.as_bytes()]).expect("bounded fixture hashes");
    assert_eq!(encode_hex(&digest), FIXTURE_SHA256_HEX);

    assert!(FIXTURE.starts_with("# PERMANENTLY NEVER-FUND\n"));
    for role in ['A', 'B', 'C'] {
        assert!(FIXTURE.contains(&format!(
            "# role-{role}: QuietKey/M24/NEVER-FUND/fixture-only/role-{role}/v1"
        )));
    }
    assert_eq!(
        field("seed_ascii"),
        "QuietKey/M24/NEVER-FUND/fixture-only/role-A/v1"
    );
    assert_eq!(
        field("message_ascii"),
        "QuietKey/M24/qk-secp/signing-boundary/v1"
    );
    assert_eq!(field("path"), "m/48'/0'/0'/2'/1/65535");
    assert_eq!(field("branch"), "1");
    assert_eq!(field("child_index"), "65535");
    assert_eq!(field("master_secret_hex").len(), 64);
    assert_eq!(field("master_chain_code_hex").len(), 64);
    assert_eq!(field("route_secret_hex"), field("step_6_secret_hex"));
    assert_eq!(field("route_chain_code_hex"), field("step_6_ir_hex"));
    assert_eq!(
        field("route_public_key_hex"),
        field("step_6_public_key_hex")
    );
    assert_eq!(field("rfc6979_nonce_hex").len(), 64);
    assert!(FIXTURE.contains(
        "# Python generator SHA-256: 93b6c3b6810599f1587c1d7d5b72a0c6ecabf35c02f2a6326eae22e1b309fa30."
    ));
    assert!(FIXTURE.contains(
        "# Ruby generator SHA-256: d938cb09563b08074aabd07d99a5cb7fdb389d3637b9024bfd4e515f9253f128."
    ));
    assert!(FIXTURE.contains(
        "# Public screening report SHA-256: 69ce2e724e0a0bbd1cdc9f4c502b6f7858f52afb9ee135f9675d14652d5cebf5; procedure SHA-256: c210fc7ecfc6e5f19242cb3f364eb1bcb850d37cb3872fba86757641a2a03458."
    ));
    assert!(FIXTURE.contains("Collisions: zero."));
}

#[test]
fn deterministic_signing_matches_fixture_and_wipes_import_source() {
    let mut source = decode_hex::<32>(field("route_secret_hex"));
    let secret = secret_key_import(&mut source).expect("public fixture scalar must import");
    assert_eq!(source, [0u8; 32]);

    let public_key_bytes = decode_hex::<33>(field("route_public_key_hex"));
    let public_key =
        pubkey_parse_compressed(&public_key_bytes).expect("public fixture key must parse");
    let digest = decode_hex::<32>(field("digest_hex"));
    let expected_der = decode_hex_vec(field("low_s_der_hex"));

    let first = ecdsa_sign_rfc6979(&secret, &digest, &public_key)
        .expect("fixture signature must self-verify");
    let second = ecdsa_sign_rfc6979(&secret, &digest, &public_key)
        .expect("repeated fixture signature must self-verify");

    let mut first_der = [0xa5u8; 72];
    let mut second_der = [0x5au8; 72];
    let first_len =
        signature_serialize_der(&first, &mut first_der).expect("first DER serialization");
    let second_len =
        signature_serialize_der(&second, &mut second_der).expect("second DER serialization");
    assert_eq!(first_len, expected_der.len());
    assert_eq!(second_len, expected_der.len());
    assert_eq!(&first_der[..first_len], expected_der.as_slice());
    assert_eq!(&second_der[..second_len], expected_der.as_slice());
    assert_eq!(&first_der[first_len..], &[0u8; 72 - 70]);
    assert_eq!(&second_der[second_len..], &[0u8; 72 - 70]);

    let reparsed = signature_parse_der(&first_der[..first_len]).expect("strict DER reparses");
    assert_eq!(ecdsa_verify(&reparsed, &digest, &public_key), Ok(()));
}

#[test]
fn wrong_expected_role_key_releases_no_signature() {
    let mut source = decode_hex::<32>(field("route_secret_hex"));
    let secret = secret_key_import(&mut source).expect("public fixture scalar must import");
    assert_eq!(source, [0u8; 32]);
    let wrong_key = pubkey_parse_compressed(&G_COMPRESSED).expect("generator must parse");
    let digest = decode_hex::<32>(field("digest_hex"));
    assert!(matches!(
        ecdsa_sign_rfc6979(&secret, &digest, &wrong_key),
        Err(SecpError::SelfVerificationFailed)
    ));
}
