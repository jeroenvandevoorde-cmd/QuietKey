//! Exact paired-descriptor parsing and bounded public script derivation.

use crate::checksum::{
    descriptor_checksum_matches, is_checksum_character, is_descriptor_character,
};
use crate::sha256::{sha256, Sha256};
use core::fmt;
use qk_bip32::{
    decode_mainnet_xpub, derive_public_child, CkdPubError, DecodedXpub, PublicNode, XpubDecodeError,
};

const DESCRIPTOR_LEN: usize = 445;
const BODY_LEN: usize = 436;
const CHECKSUM_LEN: usize = 8;
const XPUB_LEN: usize = 111;
const ACCOUNT_COUNT: usize = 3;
const WITNESS_SCRIPT_LEN: usize = 105;
const SCRIPT_PUBKEY_LEN: usize = 34;
const WALLET_TRANSCRIPT_LEN: usize = 891;
const HARDENED_BOUND: u32 = 0x8000_0000;
const ACCOUNT_CHILD_NUMBER: u32 = 0x8000_0002;
const PREFIX: &[u8; 18] = b"wsh(sortedmulti(2,";
const ORIGIN_SUFFIX: &[u8; 14] = b"/48'/0'/0'/2']";
const ORIGIN_STARTS: [usize; ACCOUNT_COUNT] = [18, 157, 296];
const XPUB_STARTS: [usize; ACCOUNT_COUNT] = [41, 180, 319];
const BRANCH_POSITIONS: [usize; ACCOUNT_COUNT] = [153, 292, 431];

/// Validated paired descriptor state. Its descriptor bytes and account
/// nodes are intentionally not observable.
pub struct DescriptorPair {
    account_nodes: [PublicNode; ACCOUNT_COUNT],
    origin_fingerprints: [[u8; 4]; ACCOUNT_COUNT],
    wallet_id: [u8; 32],
}

impl DescriptorPair {
    /// Return the exact origin fingerprints in descriptor role A/B/C
    /// order. This is role metadata only; it authenticates nothing.
    pub const fn origin_fingerprints(&self) -> [[u8; 4]; ACCOUNT_COUNT] {
        self.origin_fingerprints
    }

    /// Return the hash of the exact validated receive/checksum, raw-zero
    /// separator, and change/checksum transcript.
    pub fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }
}

/// Exact public script facts at one branch/index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedScript {
    /// Canonical 105-byte 2-of-3 compressed-key multisig script.
    pub witness_script: [u8; WITNESS_SCRIPT_LEN],
    /// Native SegWit-v0 P2WSH scriptPubKey.
    pub script_pubkey: [u8; SCRIPT_PUBKEY_LEN],
}

/// Closed paired-descriptor rejection set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorParseError {
    InvalidDescriptorLength,
    InvalidChecksumDelimiter,
    InvalidChecksumCharacter,
    InvalidDescriptorCharacter,
    ChecksumMismatch,
    NonCanonicalDescriptor,
    DescriptorPairMismatch,
    InvalidAccountXpub,
    InvalidAccountDepth,
    InvalidAccountChildNumber,
    DuplicateAccountXpub,
    CryptographicBackendInvariant,
}

impl fmt::Display for DescriptorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidDescriptorLength => "invalid descriptor length",
            Self::InvalidChecksumDelimiter => "invalid checksum delimiter",
            Self::InvalidChecksumCharacter => "invalid checksum character",
            Self::InvalidDescriptorCharacter => "invalid descriptor character",
            Self::ChecksumMismatch => "descriptor checksum mismatch",
            Self::NonCanonicalDescriptor => "descriptor is not canonical",
            Self::DescriptorPairMismatch => "descriptor pair mismatch",
            Self::InvalidAccountXpub => "invalid account xpub",
            Self::InvalidAccountDepth => "invalid account depth",
            Self::InvalidAccountChildNumber => "invalid account child number",
            Self::DuplicateAccountXpub => "duplicate account xpub",
            Self::CryptographicBackendInvariant => "cryptographic backend invariant",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DescriptorParseError {}

/// Closed public-script derivation rejection set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorDeriveError {
    HardenedIndex,
    InvalidTweak,
    PointAtInfinity,
    DuplicateDerivedKey,
    InternalInvariant,
}

impl fmt::Display for DescriptorDeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::HardenedIndex => "hardened index rejected",
            Self::InvalidTweak => "invalid tweak",
            Self::PointAtInfinity => "point at infinity",
            Self::DuplicateDerivedKey => "duplicate derived key",
            Self::InternalInvariant => "internal invariant",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DescriptorDeriveError {}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn origin_matches(body: &[u8], start: usize) -> bool {
    body[start] == b'['
        && body[start + 1..start + 9]
            .iter()
            .all(|&byte| is_lower_hex(byte))
        && &body[start + 9..start + 23] == ORIGIN_SUFFIX
}

fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_origin_fingerprints(body: &[u8]) -> Option<[[u8; 4]; ACCOUNT_COUNT]> {
    let mut fingerprints = [[0u8; 4]; ACCOUNT_COUNT];
    for (fingerprint, start) in fingerprints.iter_mut().zip(ORIGIN_STARTS) {
        for (slot, pair) in fingerprint
            .iter_mut()
            .zip(body.get(start + 1..start + 9)?.chunks_exact(2))
        {
            let high = lower_hex_value(*pair.first()?)?;
            let low = lower_hex_value(*pair.get(1)?)?;
            *slot = high.checked_mul(16)?.checked_add(low)?;
        }
    }
    Some(fingerprints)
}

fn grammar_matches(input: &[u8], branch: u8) -> bool {
    let body = &input[..BODY_LEN];
    if &body[..PREFIX.len()] != PREFIX || &body[434..436] != b"))" {
        return false;
    }
    for role in 0..ACCOUNT_COUNT {
        let origin_start = ORIGIN_STARTS[role];
        let xpub_start = XPUB_STARTS[role];
        let branch_position = BRANCH_POSITIONS[role];
        if !origin_matches(body, origin_start)
            || xpub_start != origin_start + 23
            || branch_position != xpub_start + XPUB_LEN + 1
            || body[branch_position - 1] != b'/'
            || body[branch_position] != branch
            || body[branch_position + 1] != b'/'
            || body[branch_position + 2] != b'*'
        {
            return false;
        }
        if role < ACCOUNT_COUNT - 1 && body[branch_position + 3] != b',' {
            return false;
        }
    }
    true
}

fn pair_bodies_match(receive: &[u8], change: &[u8]) -> bool {
    (0..BODY_LEN).all(|index| BRANCH_POSITIONS.contains(&index) || receive[index] == change[index])
}

fn map_decode_result(
    result: Result<DecodedXpub, XpubDecodeError>,
) -> Result<DecodedXpub, DescriptorParseError> {
    match result {
        Ok(decoded) => Ok(decoded),
        Err(XpubDecodeError::CryptographicBackendInvariant) => {
            Err(DescriptorParseError::CryptographicBackendInvariant)
        }
        Err(_) => Err(DescriptorParseError::InvalidAccountXpub),
    }
}

fn parse_with_decoder<F>(
    receive: &[u8],
    change: &[u8],
    mut decode: F,
) -> Result<DescriptorPair, DescriptorParseError>
where
    F: FnMut(&[u8]) -> Result<DecodedXpub, XpubDecodeError>,
{
    if receive.len() != DESCRIPTOR_LEN {
        return Err(DescriptorParseError::InvalidDescriptorLength);
    }
    if change.len() != DESCRIPTOR_LEN {
        return Err(DescriptorParseError::InvalidDescriptorLength);
    }
    if receive[BODY_LEN] != b'#' {
        return Err(DescriptorParseError::InvalidChecksumDelimiter);
    }
    if change[BODY_LEN] != b'#' {
        return Err(DescriptorParseError::InvalidChecksumDelimiter);
    }
    if receive[BODY_LEN + 1..BODY_LEN + 1 + CHECKSUM_LEN]
        .iter()
        .any(|&byte| !is_checksum_character(byte))
    {
        return Err(DescriptorParseError::InvalidChecksumCharacter);
    }
    if change[BODY_LEN + 1..BODY_LEN + 1 + CHECKSUM_LEN]
        .iter()
        .any(|&byte| !is_checksum_character(byte))
    {
        return Err(DescriptorParseError::InvalidChecksumCharacter);
    }
    if receive[..BODY_LEN]
        .iter()
        .any(|&byte| !is_descriptor_character(byte))
    {
        return Err(DescriptorParseError::InvalidDescriptorCharacter);
    }
    if change[..BODY_LEN]
        .iter()
        .any(|&byte| !is_descriptor_character(byte))
    {
        return Err(DescriptorParseError::InvalidDescriptorCharacter);
    }
    if !descriptor_checksum_matches(
        &receive[..BODY_LEN],
        &receive[BODY_LEN + 1..BODY_LEN + 1 + CHECKSUM_LEN],
    ) {
        return Err(DescriptorParseError::ChecksumMismatch);
    }
    if !descriptor_checksum_matches(
        &change[..BODY_LEN],
        &change[BODY_LEN + 1..BODY_LEN + 1 + CHECKSUM_LEN],
    ) {
        return Err(DescriptorParseError::ChecksumMismatch);
    }
    if !grammar_matches(receive, b'0') {
        return Err(DescriptorParseError::NonCanonicalDescriptor);
    }
    if !grammar_matches(change, b'1') {
        return Err(DescriptorParseError::NonCanonicalDescriptor);
    }
    if !pair_bodies_match(receive, change) {
        return Err(DescriptorParseError::DescriptorPairMismatch);
    }
    let origin_fingerprints = parse_origin_fingerprints(&receive[..BODY_LEN])
        .ok_or(DescriptorParseError::NonCanonicalDescriptor)?;

    let decoded = [
        decode(&receive[XPUB_STARTS[0]..XPUB_STARTS[0] + XPUB_LEN]),
        decode(&receive[XPUB_STARTS[1]..XPUB_STARTS[1] + XPUB_LEN]),
        decode(&receive[XPUB_STARTS[2]..XPUB_STARTS[2] + XPUB_LEN]),
    ];
    let decoded = [
        map_decode_result(decoded[0])?,
        map_decode_result(decoded[1])?,
        map_decode_result(decoded[2])?,
    ];
    if decoded.iter().any(|account| account.public_node.depth != 4) {
        return Err(DescriptorParseError::InvalidAccountDepth);
    }
    if decoded
        .iter()
        .any(|account| account.child_number != ACCOUNT_CHILD_NUMBER)
    {
        return Err(DescriptorParseError::InvalidAccountChildNumber);
    }
    let account_nodes = [
        decoded[0].public_node,
        decoded[1].public_node,
        decoded[2].public_node,
    ];
    if account_nodes[0] == account_nodes[1]
        || account_nodes[0] == account_nodes[2]
        || account_nodes[1] == account_nodes[2]
    {
        return Err(DescriptorParseError::DuplicateAccountXpub);
    }
    let mut hash = Sha256::new();
    hash.update(receive);
    hash.update(&[0]);
    hash.update(change);
    debug_assert_eq!(receive.len() + 1 + change.len(), WALLET_TRANSCRIPT_LEN);
    Ok(DescriptorPair {
        account_nodes,
        origin_fingerprints,
        wallet_id: hash.finalize(),
    })
}

/// Parse one exact receive/change descriptor pair without trimming,
/// normalization, serialization, or ownership inference.
pub fn parse_descriptor_pair(
    receive: &[u8],
    change: &[u8],
) -> Result<DescriptorPair, DescriptorParseError> {
    parse_with_decoder(receive, change, decode_mainnet_xpub)
}

fn map_derive_error(error: CkdPubError) -> DescriptorDeriveError {
    match error {
        CkdPubError::InvalidTweak => DescriptorDeriveError::InvalidTweak,
        CkdPubError::PointAtInfinity => DescriptorDeriveError::PointAtInfinity,
        CkdPubError::HardenedIndex | CkdPubError::DepthOverflow | CkdPubError::InvalidParentKey => {
            DescriptorDeriveError::InternalInvariant
        }
    }
}

fn sort_keys(keys: &mut [[u8; 33]; ACCOUNT_COUNT]) {
    for (left, right) in [(0, 1), (1, 2), (0, 1)] {
        if keys[left] > keys[right] {
            keys.swap(left, right);
        }
    }
}

fn assemble_script(mut keys: [[u8; 33]; ACCOUNT_COUNT]) -> DerivedScript {
    sort_keys(&mut keys);
    let mut witness_script = [0u8; WITNESS_SCRIPT_LEN];
    witness_script[0] = 0x52;
    for (role, key) in keys.iter().enumerate() {
        let offset = 1 + role * 34;
        witness_script[offset] = 0x21;
        witness_script[offset + 1..offset + 34].copy_from_slice(key);
    }
    witness_script[103] = 0x53;
    witness_script[104] = 0xae;
    let mut script_pubkey = [0u8; SCRIPT_PUBKEY_LEN];
    script_pubkey[..2].copy_from_slice(&[0x00, 0x20]);
    script_pubkey[2..].copy_from_slice(&sha256(&witness_script));
    DerivedScript {
        witness_script,
        script_pubkey,
    }
}

fn derive_role_keys_with<F>(
    pair: &DescriptorPair,
    branch: u32,
    index: u32,
    mut derive: F,
) -> Result<[[u8; 33]; ACCOUNT_COUNT], DescriptorDeriveError>
where
    F: FnMut(&PublicNode, u32) -> Result<PublicNode, CkdPubError>,
{
    if index >= HARDENED_BOUND {
        return Err(DescriptorDeriveError::HardenedIndex);
    }
    let mut keys = [[0u8; 33]; ACCOUNT_COUNT];
    for (key, parent) in keys.iter_mut().zip(pair.account_nodes.iter()) {
        let branch_node = derive(parent, branch).map_err(map_derive_error)?;
        let child_node = derive(&branch_node, index).map_err(map_derive_error)?;
        *key = child_node.compressed_public_key;
    }
    if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
        return Err(DescriptorDeriveError::DuplicateDerivedKey);
    }
    Ok(keys)
}

fn derive_with<F>(
    pair: &DescriptorPair,
    branch: u32,
    index: u32,
    derive: F,
) -> Result<DerivedScript, DescriptorDeriveError>
where
    F: FnMut(&PublicNode, u32) -> Result<PublicNode, CkdPubError>,
{
    Ok(assemble_script(derive_role_keys_with(
        pair, branch, index, derive,
    )?))
}

fn match_derivation_claims(
    pair: &DescriptorPair,
    branch: u32,
    index: u32,
    claimed_role_keys: &[[u8; 33]; ACCOUNT_COUNT],
) -> Result<Option<DerivedScript>, DescriptorDeriveError> {
    let role_keys = derive_role_keys_with(pair, branch, index, derive_public_child)?;
    if &role_keys != claimed_role_keys {
        return Ok(None);
    }
    Ok(Some(assemble_script(role_keys)))
}

/// Derive the fixed receive branch and exact supplied nonhardened index.
pub fn derive_receive_script(
    pair: &DescriptorPair,
    index: u32,
) -> Result<DerivedScript, DescriptorDeriveError> {
    derive_with(pair, 0, index, derive_public_child)
}

/// Derive the fixed change branch and exact supplied nonhardened index.
pub fn derive_change_script(
    pair: &DescriptorPair,
    index: u32,
) -> Result<DerivedScript, DescriptorDeriveError> {
    derive_with(pair, 1, index, derive_public_child)
}

/// Match supplied role A/B/C receive-branch key claims before BIP67
/// sorting and, on exact equality, return the canonical script facts.
pub fn match_receive_derivation_claims(
    pair: &DescriptorPair,
    index: u32,
    claimed_role_keys: &[[u8; 33]; ACCOUNT_COUNT],
) -> Result<Option<DerivedScript>, DescriptorDeriveError> {
    match_derivation_claims(pair, 0, index, claimed_role_keys)
}

/// Match supplied role A/B/C change-branch key claims before BIP67
/// sorting and, on exact equality, return the canonical script facts.
pub fn match_change_derivation_claims(
    pair: &DescriptorPair,
    index: u32,
    claimed_role_keys: &[[u8; 33]; ACCOUNT_COUNT],
) -> Result<Option<DerivedScript>, DescriptorDeriveError> {
    match_derivation_claims(pair, 1, index, claimed_role_keys)
}

#[cfg(test)]
mod tests {
    use super::{
        assemble_script, derive_with, match_change_derivation_claims,
        match_receive_derivation_claims, parse_descriptor_pair, parse_with_decoder, sort_keys,
        DescriptorDeriveError, DescriptorParseError, PublicNode,
    };
    use crate::sha256::Sha256;
    use qk_bip32::{CkdPubError, DecodedXpub, XpubDecodeError};

    const PAIRS: &str = include_str!("../tests/fixtures/descriptor_pairs.txt");
    const BIP67: &str = include_str!("../tests/fixtures/bip67_sort_vectors.txt");

    fn field<'a>(block: &'a str, name: &str) -> &'a str {
        let prefix = format!("{name}: ");
        block
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .expect("fixture field")
    }

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *slot = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        output
    }

    fn pair() -> super::DescriptorPair {
        let block = PAIRS
            .split("\n\n")
            .find(|block| block.contains("case: GOLDEN"))
            .unwrap();
        parse_descriptor_pair(
            field(block, "receive").as_bytes(),
            field(block, "change").as_bytes(),
        )
        .unwrap()
    }

    fn role_keys(block: &str) -> [[u8; 33]; 3] {
        [
            hex(field(block, "role_a")),
            hex(field(block, "role_b")),
            hex(field(block, "role_c")),
        ]
    }

    fn node(byte: u8) -> PublicNode {
        let mut key = [byte; 33];
        key[0] = if byte & 1 == 0 { 0x02 } else { 0x03 };
        PublicNode {
            depth: 4,
            chain_code: [byte; 32],
            compressed_public_key: key,
        }
    }

    #[test]
    fn bip67_vectors_cover_noop_reorder_and_exact_scripts() {
        let blocks: Vec<&str> = BIP67
            .split("\n\n")
            .filter(|block| block.contains("case: "))
            .collect();
        assert_eq!(blocks.len(), 2);
        for block in blocks {
            let mut keys = [
                hex(field(block, "input_0")),
                hex(field(block, "input_1")),
                hex(field(block, "input_2")),
            ];
            sort_keys(&mut keys);
            assert_eq!(keys[0], hex(field(block, "sorted_0")));
            assert_eq!(keys[1], hex(field(block, "sorted_1")));
            assert_eq!(keys[2], hex(field(block, "sorted_2")));
            let script = assemble_script(keys);
            assert_eq!(script.witness_script, hex(field(block, "witness_script")));
            assert_eq!(script.script_pubkey, hex(field(block, "script_pubkey")));
        }
    }

    #[test]
    fn all_six_key_permutations_sort_identically() {
        let mut sorted = [
            node(2).compressed_public_key,
            node(3).compressed_public_key,
            node(4).compressed_public_key,
        ];
        sorted.sort();
        for permutation in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut candidate = [
                sorted[permutation[0]],
                sorted[permutation[1]],
                sorted[permutation[2]],
            ];
            sort_keys(&mut candidate);
            assert_eq!(candidate, sorted);
        }
    }

    #[test]
    fn derive_seam_uses_six_calls_in_role_branch_index_order() {
        let pair = pair();
        let mut calls = Vec::new();
        let result = derive_with(&pair, 1, 7, |parent, index| {
            calls.push((parent.depth, parent.compressed_public_key, index));
            let mut child = *parent;
            child.depth += 1;
            child.compressed_public_key[1] ^= (index as u8).wrapping_add(child.depth);
            Ok(child)
        });
        assert!(result.is_ok());
        assert_eq!(calls.len(), 6);
        assert_eq!(
            calls.iter().map(|call| call.2).collect::<Vec<_>>(),
            [1, 7, 1, 7, 1, 7]
        );
        assert_eq!(calls[0].0, 4);
        assert_eq!(calls[1].0, 5);
        assert_eq!(calls[2].0, 4);
        assert_eq!(calls[3].0, 5);
        assert_eq!(calls[4].0, 4);
        assert_eq!(calls[5].0, 5);
    }

    #[test]
    fn origin_fingerprints_are_role_ordered_and_claims_match_before_sorting() {
        let golden = PAIRS
            .split("\n\n")
            .find(|block| block.contains("case: GOLDEN"))
            .unwrap();
        let receive_zero = golden
            .split("derivation: ")
            .find(|block| block.starts_with("receive-0\n"))
            .unwrap();
        let change_zero = golden
            .split("derivation: ")
            .find(|block| block.starts_with("change-0\n"))
            .unwrap();
        let pair = pair();
        assert_eq!(
            pair.origin_fingerprints(),
            [
                [0x11, 0x22, 0x33, 0x44],
                [0x55, 0x66, 0x77, 0x88],
                [0x99, 0xaa, 0xbb, 0xcc],
            ]
        );

        let receive_keys = role_keys(receive_zero);
        let receive = match_receive_derivation_claims(&pair, 0, &receive_keys).unwrap();
        assert_eq!(
            receive.unwrap().witness_script,
            hex(field(receive_zero, "witness_script"))
        );
        let mut reordered = receive_keys;
        reordered.swap(0, 1);
        assert_eq!(
            match_receive_derivation_claims(&pair, 0, &reordered).unwrap(),
            None
        );

        let change_keys = role_keys(change_zero);
        let change = match_change_derivation_claims(&pair, 0, &change_keys).unwrap();
        assert_eq!(
            change.unwrap().script_pubkey,
            hex(field(change_zero, "script_pubkey"))
        );
    }

    #[test]
    fn hardened_index_rejects_before_private_seam_call() {
        let pair = pair();
        for index in [0x8000_0000, u32::MAX] {
            let result = derive_with(&pair, 0, index, |_, _| panic!("deriver must not be called"));
            assert_eq!(result, Err(DescriptorDeriveError::HardenedIndex));
        }
    }

    #[test]
    fn derive_error_mapping_has_no_fallback() {
        let pair = pair();
        for (source, expected) in [
            (
                CkdPubError::InvalidTweak,
                DescriptorDeriveError::InvalidTweak,
            ),
            (
                CkdPubError::PointAtInfinity,
                DescriptorDeriveError::PointAtInfinity,
            ),
            (
                CkdPubError::HardenedIndex,
                DescriptorDeriveError::InternalInvariant,
            ),
            (
                CkdPubError::DepthOverflow,
                DescriptorDeriveError::InternalInvariant,
            ),
            (
                CkdPubError::InvalidParentKey,
                DescriptorDeriveError::InternalInvariant,
            ),
        ] {
            let result = derive_with(&pair, 0, 0, |_, _| Err(source));
            assert_eq!(result, Err(expected));
        }
    }

    #[test]
    fn duplicate_derived_key_private_seam_rejects_before_script() {
        let pair = pair();
        let repeated = node(8);
        let distinct = node(9);
        let mut call = 0usize;
        let result = derive_with(&pair, 0, 0, |_, _| {
            let role = call / 2;
            call += 1;
            Ok(if role < 2 { repeated } else { distinct })
        });
        assert_eq!(call, 6);
        assert_eq!(result, Err(DescriptorDeriveError::DuplicateDerivedKey));
    }

    #[test]
    fn parser_seam_calls_all_three_decoders_and_maps_errors() {
        let block = PAIRS
            .split("\n\n")
            .find(|block| block.contains("case: GOLDEN"))
            .unwrap();
        let receive = field(block, "receive").as_bytes();
        let change = field(block, "change").as_bytes();
        let valid = DecodedXpub {
            public_node: node(2),
            parent_fingerprint: [0; 4],
            child_number: 0x8000_0002,
        };
        let mut count = 0;
        let ordinary = parse_with_decoder(receive, change, |_| {
            count += 1;
            if count == 2 {
                Err(XpubDecodeError::ChecksumMismatch)
            } else {
                Ok(DecodedXpub {
                    public_node: node(count as u8 + 1),
                    ..valid
                })
            }
        });
        assert_eq!(count, 3);
        assert!(matches!(
            ordinary,
            Err(DescriptorParseError::InvalidAccountXpub)
        ));

        let invariant = parse_with_decoder(receive, change, |_| {
            Err(XpubDecodeError::CryptographicBackendInvariant)
        });
        assert!(matches!(
            invariant,
            Err(DescriptorParseError::CryptographicBackendInvariant)
        ));
    }

    #[test]
    fn parser_profile_stages_depth_child_then_duplicate() {
        let block = PAIRS
            .split("\n\n")
            .find(|block| block.contains("case: GOLDEN"))
            .unwrap();
        let receive = field(block, "receive").as_bytes();
        let change = field(block, "change").as_bytes();
        let run = |nodes: [PublicNode; 3], children: [u32; 3]| {
            let mut role = 0usize;
            parse_with_decoder(receive, change, |_| {
                let result = DecodedXpub {
                    public_node: nodes[role],
                    parent_fingerprint: [0; 4],
                    child_number: children[role],
                };
                role += 1;
                Ok(result)
            })
        };
        let mut depth = node(2);
        depth.depth = 3;
        assert!(matches!(
            run(
                [depth, node(3), node(4)],
                [0x8000_0001, 0x8000_0002, 0x8000_0002]
            ),
            Err(DescriptorParseError::InvalidAccountDepth)
        ));
        assert!(matches!(
            run(
                [node(2), node(3), node(4)],
                [0x8000_0001, 0x8000_0002, 0x8000_0002]
            ),
            Err(DescriptorParseError::InvalidAccountChildNumber)
        ));
        assert!(matches!(
            run([node(2), node(2), node(4)], [0x8000_0002; 3]),
            Err(DescriptorParseError::DuplicateAccountXpub)
        ));
    }

    #[test]
    fn wallet_transcript_includes_both_checksums_and_one_raw_zero() {
        let block = PAIRS
            .split("\n\n")
            .find(|block| block.contains("case: GOLDEN"))
            .unwrap();
        let receive = field(block, "receive").as_bytes();
        let change = field(block, "change").as_bytes();
        let pair = parse_descriptor_pair(receive, change).unwrap();

        let mut exact = Sha256::new();
        exact.update(receive);
        exact.update(&[0]);
        exact.update(change);
        assert_eq!(pair.wallet_id(), exact.finalize());

        let mut text_separator = Sha256::new();
        text_separator.update(receive);
        text_separator.update(b"00");
        text_separator.update(change);
        assert_ne!(pair.wallet_id(), text_separator.finalize());

        let mut without_checksums = Sha256::new();
        without_checksums.update(&receive[..436]);
        without_checksums.update(&[0]);
        without_checksums.update(&change[..436]);
        assert_ne!(pair.wallet_id(), without_checksums.finalize());

        let mut changed_checksum = [0u8; 445];
        changed_checksum.copy_from_slice(receive);
        changed_checksum[444] ^= 1;
        let mut changed = Sha256::new();
        changed.update(&changed_checksum);
        changed.update(&[0]);
        changed.update(change);
        assert_ne!(pair.wallet_id(), changed.finalize());
    }
}
