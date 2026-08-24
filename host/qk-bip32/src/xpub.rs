//! Strict bounded HOST-only mainnet xpub decoder (QK-DEC-051..053).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! The decoder accepts borrowed bytes, performs complete lexical
//! validation, decodes into one fixed 82-byte accumulator, checks the
//! checksum before interpreting payload fields, and accepts only the
//! mainnet public version. It exposes no encoder or serializer and
//! performs no allocation, I/O, network access, randomness, logging,
//! or recursion. Public-key validation uses only the unchanged
//! qk-secp parse/serialize boundary. No BIP32 conformance claim.

use crate::sha256::sha256d_payload;
use crate::PublicNode;
use core::fmt;

const MAX_INPUT_BYTES: usize = 112;
const DECODED_BYTES: usize = 82;
const PAYLOAD_BYTES: usize = 78;
const MAINNET_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

/// Strictly decoded public fields from one mainnet xpub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedXpub {
    /// Public BIP32 node fields carried by the extended public key.
    pub public_node: PublicNode,
    /// Serialized parent fingerprint metadata; not recomputed here.
    pub parent_fingerprint: [u8; 4],
    /// Serialized child-number metadata, including the hardened range.
    pub child_number: u32,
}

/// Closed rejection set for strict mainnet xpub decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpubDecodeError {
    /// Input exceeds the 112-byte bound.
    InputTooLong,
    /// At least one byte is outside the exact Bitcoin Base58 alphabet.
    InvalidBase58Character,
    /// Base58 arithmetic overflowed or did not decode to exactly 82 bytes.
    DecodedLength,
    /// The four checksum bytes do not equal SHA256d(payload)[0..4].
    ChecksumMismatch,
    /// The payload version is not mainnet xpub 0488b21e.
    UnsupportedVersion,
    /// A depth-zero node carries a nonzero parent fingerprint.
    InvalidRootParentFingerprint,
    /// A depth-zero node carries a nonzero child number.
    InvalidRootChildNumber,
    /// The public-key field does not begin with 02 or 03.
    InvalidPublicKeyPrefix,
    /// The compressed public key is not a valid secp256k1 point.
    InvalidPublicKey,
    /// The qk-secp boundary reported an unexpected invariant status.
    CryptographicBackendInvariant,
}

impl fmt::Display for XpubDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InputTooLong => "input too long",
            Self::InvalidBase58Character => "invalid base58 character",
            Self::DecodedLength => "decoded length invalid",
            Self::ChecksumMismatch => "checksum mismatch",
            Self::UnsupportedVersion => "unsupported extended key version",
            Self::InvalidRootParentFingerprint => "root parent fingerprint must be zero",
            Self::InvalidRootChildNumber => "root child number must be zero",
            Self::InvalidPublicKeyPrefix => "invalid public key prefix",
            Self::InvalidPublicKey => "invalid public key",
            Self::CryptographicBackendInvariant => "cryptographic backend invariant",
        };
        f.write_str(text)
    }
}

impl std::error::Error for XpubDecodeError {}

fn base58_value(byte: u8) -> Option<u8> {
    match byte {
        b'1'..=b'9' => Some(byte - b'1'),
        b'A'..=b'H' => Some(byte - b'A' + 9),
        b'J'..=b'N' => Some(byte - b'J' + 17),
        b'P'..=b'Z' => Some(byte - b'P' + 22),
        b'a'..=b'k' => Some(byte - b'a' + 33),
        b'm'..=b'z' => Some(byte - b'm' + 44),
        _ => None,
    }
}

fn decode_valid_base58(input: &[u8]) -> Result<[u8; DECODED_BYTES], XpubDecodeError> {
    let mut accumulator = [0u8; DECODED_BYTES];
    let mut overflow = false;
    for &byte in input {
        let Some(digit) = base58_value(byte) else {
            return Err(XpubDecodeError::InvalidBase58Character);
        };
        let mut carry = u16::from(digit);
        for slot in accumulator.iter_mut().rev() {
            let value = u16::from(*slot).saturating_mul(58).saturating_add(carry);
            *slot = (value & 0xff) as u8;
            carry = value >> 8;
        }
        overflow |= carry != 0;
    }
    let leading_zeroes = input.iter().take_while(|&&byte| byte == b'1').count();
    let first_significant = accumulator
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(DECODED_BYTES);
    let significant_len = DECODED_BYTES - first_significant;
    if overflow || leading_zeroes.saturating_add(significant_len) != DECODED_BYTES {
        return Err(XpubDecodeError::DecodedLength);
    }
    let mut decoded = [0u8; DECODED_BYTES];
    let Some(destination) = decoded.get_mut(leading_zeroes..) else {
        return Err(XpubDecodeError::DecodedLength);
    };
    let Some(source) = accumulator.get(first_significant..) else {
        return Err(XpubDecodeError::DecodedLength);
    };
    if destination.len() != source.len() {
        return Err(XpubDecodeError::DecodedLength);
    }
    destination.copy_from_slice(source);
    Ok(decoded)
}

fn validate_public_key_with<Parse, Serialize>(
    input: &[u8; 33],
    parse: Parse,
    serialize: Serialize,
) -> Result<(), XpubDecodeError>
where
    Parse: FnOnce(&[u8; 33]) -> Result<qk_secp::PublicKey, qk_secp::SecpError>,
    Serialize: FnOnce(&qk_secp::PublicKey) -> Result<[u8; 33], qk_secp::SecpError>,
{
    if !matches!(input[0], 0x02 | 0x03) {
        return Err(XpubDecodeError::InvalidPublicKeyPrefix);
    }
    let parsed = match parse(input) {
        Ok(key) => key,
        Err(qk_secp::SecpError::PubkeyParseFailed) => {
            return Err(XpubDecodeError::InvalidPublicKey);
        }
        Err(_) => return Err(XpubDecodeError::CryptographicBackendInvariant),
    };
    let serialized = match serialize(&parsed) {
        Ok(bytes) => bytes,
        Err(_) => return Err(XpubDecodeError::CryptographicBackendInvariant),
    };
    if serialized != *input {
        return Err(XpubDecodeError::CryptographicBackendInvariant);
    }
    Ok(())
}

fn interpret_payload_with<Validate>(
    payload: &[u8; PAYLOAD_BYTES],
    validate: Validate,
) -> Result<DecodedXpub, XpubDecodeError>
where
    Validate: FnOnce(&[u8; 33]) -> Result<(), XpubDecodeError>,
{
    if payload[..4] != MAINNET_XPUB_VERSION {
        return Err(XpubDecodeError::UnsupportedVersion);
    }
    let depth = payload[4];
    let mut parent_fingerprint = [0u8; 4];
    parent_fingerprint.copy_from_slice(&payload[5..9]);
    let mut child_number_bytes = [0u8; 4];
    child_number_bytes.copy_from_slice(&payload[9..13]);
    if depth == 0 && parent_fingerprint != [0u8; 4] {
        return Err(XpubDecodeError::InvalidRootParentFingerprint);
    }
    if depth == 0 && child_number_bytes != [0u8; 4] {
        return Err(XpubDecodeError::InvalidRootChildNumber);
    }
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(&payload[45..78]);
    validate(&compressed_public_key)?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&payload[13..45]);
    Ok(DecodedXpub {
        public_node: PublicNode {
            depth,
            chain_code,
            compressed_public_key,
        },
        parent_fingerprint,
        child_number: u32::from_be_bytes(child_number_bytes),
    })
}

/// Decode one exact, case-sensitive Bitcoin Base58Check mainnet xpub
/// from borrowed bytes into its public node and metadata fields.
///
/// The input is never trimmed or normalized. Checksum validation
/// precedes every payload semantic gate. No parent linkage is inferred,
/// and hardened child-number metadata is accepted at depth above zero.
pub fn decode_mainnet_xpub(input: &[u8]) -> Result<DecodedXpub, XpubDecodeError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(XpubDecodeError::InputTooLong);
    }
    if input.iter().any(|&byte| base58_value(byte).is_none()) {
        return Err(XpubDecodeError::InvalidBase58Character);
    }
    let decoded = decode_valid_base58(input)?;
    let mut payload = [0u8; PAYLOAD_BYTES];
    payload.copy_from_slice(&decoded[..PAYLOAD_BYTES]);
    let checksum = sha256d_payload(&payload);
    if decoded[PAYLOAD_BYTES..] != checksum[..4] {
        return Err(XpubDecodeError::ChecksumMismatch);
    }
    interpret_payload_with(&payload, |public_key| {
        validate_public_key_with(
            public_key,
            qk_secp::pubkey_parse_compressed,
            qk_secp::pubkey_serialize_compressed,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        base58_value, decode_valid_base58, interpret_payload_with, validate_public_key_with,
        XpubDecodeError, DECODED_BYTES, MAINNET_XPUB_VERSION,
    };
    use crate::sha256::sha256d_payload;

    const VECTORS: &str = include_str!("../tests/fixtures/xpub_vectors.txt");
    const VALID_KEY: [u8; 33] = [
        0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0,
        0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4,
        0x9c, 0x85, 0xc2,
    ];

    fn valid_payload() -> [u8; 78] {
        let mut payload = [0u8; 78];
        payload[..4].copy_from_slice(&MAINNET_XPUB_VERSION);
        payload[13..45].copy_from_slice(&[0x42; 32]);
        payload[45..].copy_from_slice(&VALID_KEY);
        payload
    }

    fn accept_key(_: &[u8; 33]) -> Result<(), XpubDecodeError> {
        Ok(())
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let text = core::str::from_utf8(pair).expect("ASCII hex");
            *slot = u8::from_str_radix(text, 16).expect("hex byte");
        }
        output
    }

    #[test]
    fn alphabet_mapping_is_exact() {
        let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        assert_eq!(alphabet.len(), 58);
        for (index, &byte) in alphabet.iter().enumerate() {
            assert_eq!(base58_value(byte), Some(index as u8));
        }
        for byte in 0u8..=u8::MAX {
            if !alphabet.contains(&byte) {
                assert_eq!(base58_value(byte), None);
            }
        }
    }

    #[test]
    fn leading_zero_carry_and_overflow_boundaries_are_fixed() {
        assert_eq!(decode_valid_base58(&[b'1'; 82]), Ok([0u8; 82]));
        assert_eq!(
            decode_valid_base58(&[b'1'; 81]),
            Err(XpubDecodeError::DecodedLength)
        );
        assert_eq!(
            decode_valid_base58(&[b'1'; 83]),
            Err(XpubDecodeError::DecodedLength)
        );
        assert_eq!(
            decode_valid_base58(&[b'z'; 112]),
            Err(XpubDecodeError::DecodedLength)
        );
        let token = b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let decoded = decode_valid_base58(token).expect("official 82-byte case");
        assert_eq!(&decoded[..4], &MAINNET_XPUB_VERSION);
        assert_eq!(decoded.len(), DECODED_BYTES);
    }

    #[test]
    fn all_fixture_payload_checksums_reproduce() {
        let mut count = 0usize;
        for block in VECTORS.split("\n\n") {
            let Some(token) = block.lines().find_map(|line| line.strip_prefix("token: ")) else {
                continue;
            };
            let expected_text = block
                .lines()
                .find_map(|line| line.strip_prefix("expected: "))
                .expect("expected field");
            let checksum_text = block
                .lines()
                .find_map(|line| line.strip_prefix("checksum: "))
                .expect("checksum field");
            let decoded = decode_valid_base58(token.as_bytes()).expect("82-byte fixture");
            let mut payload = [0u8; 78];
            payload.copy_from_slice(&decoded[..78]);
            let actual = sha256d_payload(&payload);
            let recorded = decode_hex::<4>(checksum_text);
            if expected_text == "ChecksumMismatch" {
                assert_eq!(recorded, [0xab, 0x47, 0x3b, 0x22]);
                assert_eq!(&actual[..4], &[0xab, 0x47, 0x3b, 0x21]);
            } else {
                assert_eq!(&actual[..4], &recorded);
            }
            count += 1;
        }
        assert_eq!(count, 19);
    }

    #[test]
    fn payload_precedence_is_version_then_root_metadata_then_key() {
        let mut payload = valid_payload();
        payload[..4].copy_from_slice(&[0x04, 0x35, 0x87, 0xcf]);
        payload[5..9].copy_from_slice(&[1; 4]);
        payload[9..13].copy_from_slice(&[2; 4]);
        payload[45] = 0x04;
        assert_eq!(
            interpret_payload_with(&payload, |_| panic!("key gate must not run")),
            Err(XpubDecodeError::UnsupportedVersion)
        );
        payload[..4].copy_from_slice(&MAINNET_XPUB_VERSION);
        assert_eq!(
            interpret_payload_with(&payload, |_| panic!("key gate must not run")),
            Err(XpubDecodeError::InvalidRootParentFingerprint)
        );
        payload[5..9].fill(0);
        assert_eq!(
            interpret_payload_with(&payload, |_| panic!("key gate must not run")),
            Err(XpubDecodeError::InvalidRootChildNumber)
        );
        payload[9..13].fill(0);
        assert_eq!(
            interpret_payload_with(&payload, |key| {
                assert_eq!(key[0], 0x04);
                Err(XpubDecodeError::InvalidPublicKeyPrefix)
            }),
            Err(XpubDecodeError::InvalidPublicKeyPrefix)
        );
    }

    #[test]
    fn every_non_mainnet_version_shares_one_rejection() {
        for version in [
            [0u8; 4],
            [0x04, 0x35, 0x87, 0xcf],
            [0x01, 0x01, 0x01, 0x01],
            [0x04, 0x88, 0xad, 0xe4],
            [0x04, 0x35, 0x83, 0x94],
            [0xff; 4],
        ] {
            let mut payload = valid_payload();
            payload[..4].copy_from_slice(&version);
            assert_eq!(
                interpret_payload_with(&payload, accept_key),
                Err(XpubDecodeError::UnsupportedVersion)
            );
        }
        assert!(interpret_payload_with(&valid_payload(), accept_key).is_ok());
    }

    #[test]
    fn depth_above_zero_accepts_all_public_child_metadata() {
        for depth in [1u8, 2, 254, 255] {
            for child in [0u32, 0x8000_0000, 0xffff_fffe, u32::MAX] {
                let mut payload = valid_payload();
                payload[4] = depth;
                payload[9..13].copy_from_slice(&child.to_be_bytes());
                let decoded = interpret_payload_with(&payload, accept_key).expect("accepted");
                assert_eq!(decoded.public_node.depth, depth);
                assert_eq!(decoded.child_number, child);
                assert_eq!(decoded.parent_fingerprint, [0u8; 4]);
            }
        }
    }

    #[test]
    fn root_metadata_errors_are_independent() {
        let mut payload = valid_payload();
        payload[5..9].copy_from_slice(&[1, 0, 0, 0]);
        assert_eq!(
            interpret_payload_with(&payload, accept_key),
            Err(XpubDecodeError::InvalidRootParentFingerprint)
        );
        payload[5..9].fill(0);
        payload[9..13].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(
            interpret_payload_with(&payload, accept_key),
            Err(XpubDecodeError::InvalidRootChildNumber)
        );
    }

    #[test]
    fn key_prefix_parse_and_backend_statuses_map_exactly() {
        for prefix in [0x01u8, 0x04] {
            let mut key = VALID_KEY;
            key[0] = prefix;
            assert_eq!(
                validate_public_key_with(
                    &key,
                    |_| panic!("parse must not run for invalid prefix"),
                    |_| panic!("serialize must not run for invalid prefix")
                ),
                Err(XpubDecodeError::InvalidPublicKeyPrefix)
            );
        }
        assert_eq!(
            validate_public_key_with(
                &VALID_KEY,
                |_| Err(qk_secp::SecpError::PubkeyParseFailed),
                |_| panic!("serialize must not run after parse rejection")
            ),
            Err(XpubDecodeError::InvalidPublicKey)
        );
        assert_eq!(
            validate_public_key_with(
                &VALID_KEY,
                |_| Err(qk_secp::SecpError::UnknownReturnCode),
                |_| panic!("serialize must not run after abnormal parse status")
            ),
            Err(XpubDecodeError::CryptographicBackendInvariant)
        );
        assert_eq!(
            validate_public_key_with(&VALID_KEY, qk_secp::pubkey_parse_compressed, |_| Err(
                qk_secp::SecpError::UnknownReturnCode
            )),
            Err(XpubDecodeError::CryptographicBackendInvariant)
        );
    }
}
