//! Deterministic M24 signing-boundary fixture and failure checks.

use qk_secp::{
    ecdsa_sign_rfc6979, ecdsa_verify, pubkey_parse_compressed, secret_key_import,
    signature_parse_der, signature_serialize_der, SecpError,
};

const FIXTURE: &str = include_str!("fixtures/m24_signing_boundary.txt");
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

#[test]
fn fixture_is_explicitly_public_and_permanently_never_fund() {
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
    assert_eq!(field("master_secret_hex").len(), 64);
    assert_eq!(field("chain_code_hex").len(), 64);
    assert_eq!(field("rfc6979_nonce_hex").len(), 64);
}

#[test]
fn deterministic_signing_matches_fixture_and_wipes_import_source() {
    let mut source = decode_hex::<32>(field("master_secret_hex"));
    let secret = secret_key_import(&mut source).expect("public fixture scalar must import");
    assert_eq!(source, [0u8; 32]);

    let public_key_bytes = decode_hex::<33>(field("compressed_public_key_hex"));
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
    let mut source = decode_hex::<32>(field("master_secret_hex"));
    let secret = secret_key_import(&mut source).expect("public fixture scalar must import");
    assert_eq!(source, [0u8; 32]);
    let wrong_key = pubkey_parse_compressed(&G_COMPRESSED).expect("generator must parse");
    let digest = decode_hex::<32>(field("digest_hex"));
    assert!(matches!(
        ecdsa_sign_rfc6979(&secret, &digest, &wrong_key),
        Err(SecpError::SelfVerificationFailed)
    ));
}
