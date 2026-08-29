use qk_kit::{
    decode_fallback, encode_fallback, encode_frame, encode_qr, frame_metadata, FrameMetadata,
    KitError, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN, QR_PACKED_BYTES,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/kit_share_v2.txt");
const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const PREFIX_LEN: usize = 134;
const CHECKSUM_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";
const QR_CORE_SIDE: usize = 57;
const QR_FULL_SIDE: usize = 65;
const QR_QUIET_ZONE: usize = 4;
const QR_CORE_PACKED_BYTES: usize = 407;

struct FixtureCase {
    share_index: ShareIndex,
    wallet_id: [u8; 32],
    share: [u8; 96],
    frame: [u8; FRAME_LEN],
    fallback: [u8; FALLBACK_SYMBOLS],
    mask: u8,
    penalties: [u32; 8],
    core_matrix: [u8; QR_CORE_PACKED_BYTES],
    quiet_matrix: [u8; QR_PACKED_BYTES],
}

fn field(name: &str) -> &'static str {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = core::str::from_utf8(line).expect("fixture is ASCII");
            let (candidate, value) = line.split_once(": ")?;
            (candidate == name).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("fixture hex must be canonical lowercase"),
    }
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2, "fixture hex width");
    let mut result = [0u8; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "even fixture hex width");
    for (output, pair) in result.iter_mut().zip(pairs.iter()) {
        *output = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    result
}

fn penalties(value: &str) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut fields = value.split(',');
    for output in &mut result {
        *output = fields
            .next()
            .expect("eight penalty fields")
            .parse()
            .expect("decimal penalty");
    }
    assert!(fields.next().is_none(), "exact penalty field count");
    result
}

fn fixture_case(number: u8, share_index: ShareIndex) -> FixtureCase {
    assert!(number == 1 || number == 2);
    let wallet_id = hex_array(field("wallet_id_hex"));
    let share = hex_array(field(&format!("share_{number}_hex")));
    let frame = hex_array(field(&format!("frame_{number}_hex")));
    let fallback = field(&format!("fallback_{number}_ascii"))
        .as_bytes()
        .try_into()
        .expect("exact fallback width");
    let mask = field(&format!("qr_{number}_mask"))
        .parse()
        .expect("decimal QR mask");
    let penalties = penalties(field(&format!("qr_{number}_penalties")));
    let core_matrix = hex_array(field(&format!("qr_{number}_core_packed_hex")));
    let quiet_matrix = hex_array(field(&format!("qr_{number}_quiet_packed_hex")));
    FixtureCase {
        share_index,
        wallet_id,
        share,
        frame,
        fallback,
        mask,
        penalties,
        core_matrix,
        quiet_matrix,
    }
}

#[test]
fn registered_fixture_identity_and_geometry_are_exact() {
    assert_eq!(FIXTURE.len(), 14_849);
    assert_eq!(FIXTURE.iter().filter(|byte| **byte == b'\n').count(), 87);
    assert_eq!(FIXTURE.last(), Some(&b'\n'));
    assert_eq!(
        sha256(FIXTURE),
        hex_array::<32>("0ab559508e65c7758aa183975db620b3506cebd9ab63cf50a27e14ca6daf80f7")
    );
    assert_eq!(
        field("format"),
        "QUIETKEY_V2_SLICE7_KIT_CODEC_PUBLIC_FACTS_V1"
    );
    assert_eq!(
        field("funding_status"),
        "PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL"
    );
    for number in [1, 2] {
        assert_eq!(field(&format!("frame_{number}_len")), "142");
        assert_eq!(field(&format!("fallback_{number}_len")), "228");
        assert_eq!(field(&format!("qr_{number}_version")), "10");
        assert_eq!(field(&format!("qr_{number}_ecc")), "Q");
        assert_eq!(field(&format!("qr_{number}_mode")), "byte");
        assert_eq!(field(&format!("qr_{number}_eci")), "none");
        assert_eq!(field(&format!("qr_{number}_quiet_zone")), "4");
        assert_eq!(field(&format!("qr_{number}_quiet_size")), "65");
        assert_eq!(field(&format!("qr_{number}_core_packed_len")), "407");
        assert_eq!(field(&format!("qr_{number}_quiet_packed_len")), "529");
    }
}

#[test]
fn frame_construction_and_metadata_match_both_registered_cases() {
    for case in [
        fixture_case(1, ShareIndex::One),
        fixture_case(2, ShareIndex::Two),
    ] {
        assert_eq!(
            encode_frame(case.share_index, &case.wallet_id, &case.share),
            case.frame
        );
        assert_eq!(
            frame_metadata(&case.frame),
            Ok(FrameMetadata {
                share_index: case.share_index,
                wallet_id: case.wallet_id,
            })
        );
    }
}

#[test]
fn fallback_tokens_and_round_trips_match_both_registered_cases() {
    for case in [
        fixture_case(1, ShareIndex::One),
        fixture_case(2, ShareIndex::Two),
    ] {
        let mut encoded = [0xa5; FALLBACK_SYMBOLS];
        assert_eq!(encode_fallback(&case.frame, &mut encoded), Ok(()));
        assert_eq!(encoded, case.fallback);
        assert_eq!(symbol_value(encoded[FALLBACK_SYMBOLS - 1]) & 0x0f, 0);

        let mut decoded = [0x5a; FRAME_LEN];
        assert_eq!(
            decode_fallback(&case.fallback, &mut decoded),
            Ok(FrameMetadata {
                share_index: case.share_index,
                wallet_id: case.wallet_id,
            })
        );
        assert_eq!(decoded, case.frame);
    }
}

#[test]
fn qr_masks_penalties_and_quiet_matrices_match_both_registered_cases() {
    for case in [
        fixture_case(1, ShareIndex::One),
        fixture_case(2, ShareIndex::Two),
    ] {
        let mut encoded = [0xa5; QR_PACKED_BYTES];
        let metadata = encode_qr(&case.frame, &mut encoded).expect("registered frame encodes");
        assert_eq!(metadata.mask, case.mask);
        assert_eq!(metadata.penalties, case.penalties);
        assert_eq!(
            metadata.penalties[usize::from(metadata.mask)],
            *metadata.penalties.iter().min().expect("eight masks")
        );
        assert_eq!(encoded, case.quiet_matrix);
        assert_eq!(extract_core(&encoded), case.core_matrix);
        assert_eq!(encoded[QR_PACKED_BYTES - 1] & 0x7f, 0);
    }
}

#[test]
fn frame_rejection_precedence_is_exact() {
    let canonical = fixture_case(1, ShareIndex::One).frame;
    assert_eq!(
        frame_metadata(&canonical[..FRAME_LEN - 1]),
        Err(KitError::FrameLength)
    );

    let mut candidate = canonical;
    candidate[0] ^= 1;
    candidate[4] = 2;
    candidate[5] = 0;
    assert_eq!(frame_metadata(&candidate), Err(KitError::FrameChecksum));

    rewrite_checksum(&mut candidate);
    assert_eq!(frame_metadata(&candidate), Err(KitError::InvalidMagic));

    candidate[..4].copy_from_slice(b"QKKS");
    rewrite_checksum(&mut candidate);
    assert_eq!(
        frame_metadata(&candidate),
        Err(KitError::UnsupportedVersion)
    );

    candidate[4] = 1;
    rewrite_checksum(&mut candidate);
    assert_eq!(frame_metadata(&candidate), Err(KitError::InvalidShareIndex));
}

#[test]
fn fallback_rejection_precedence_and_output_immutability_are_exact() {
    let case = fixture_case(1, ShareIndex::One);
    let sentinel = [0x5a; FRAME_LEN];

    let mut output = sentinel;
    assert_eq!(
        decode_fallback(&case.fallback[..FALLBACK_SYMBOLS - 1], &mut output),
        Err(KitError::FallbackLength)
    );
    assert_eq!(output, sentinel);

    let mut malformed = case.fallback;
    malformed[0] = b'0';
    malformed[FALLBACK_SYMBOLS - 1] = ALPHABET[1];
    assert_rejected_without_output(&malformed, KitError::MalformedSymbol, sentinel);

    let mut noncanonical_padding = case.fallback;
    noncanonical_padding[0] = alternate_symbol(noncanonical_padding[0]);
    noncanonical_padding[FALLBACK_SYMBOLS - 1] = ALPHABET[1];
    assert_rejected_without_output(
        &noncanonical_padding,
        KitError::NonCanonicalPadding,
        sentinel,
    );

    let mut bad_frame = case.fallback;
    bad_frame[0] = alternate_symbol(bad_frame[0]);
    assert_rejected_without_output(&bad_frame, KitError::FrameChecksum, sentinel);

    let mut bad_frame_bytes = case.frame;
    bad_frame_bytes[FRAME_LEN - 1] ^= 1;
    let mut fallback_output = [0xa5; FALLBACK_SYMBOLS];
    let fallback_sentinel = fallback_output;
    assert_eq!(
        encode_fallback(&bad_frame_bytes, &mut fallback_output),
        Err(KitError::FrameChecksum)
    );
    assert_eq!(fallback_output, fallback_sentinel);
}

#[test]
fn qr_rejection_leaves_the_complete_output_unchanged() {
    let mut frame = fixture_case(2, ShareIndex::Two).frame;
    frame[FRAME_LEN - 1] ^= 1;
    let mut output = [0xa5; QR_PACKED_BYTES];
    let sentinel = output;
    assert_eq!(encode_qr(&frame, &mut output), Err(KitError::FrameChecksum));
    assert_eq!(output, sentinel);
}

fn symbol_value(symbol: u8) -> u8 {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .expect("registered fallback alphabet") as u8
}

fn alternate_symbol(symbol: u8) -> u8 {
    let value = symbol_value(symbol);
    ALPHABET[usize::from(value ^ 1)]
}

fn extract_core(quiet: &[u8; QR_PACKED_BYTES]) -> [u8; QR_CORE_PACKED_BYTES] {
    let mut core = [0u8; QR_CORE_PACKED_BYTES];
    for y in 0..QR_CORE_SIDE {
        for x in 0..QR_CORE_SIDE {
            let quiet_bit = (y + QR_QUIET_ZONE) * QR_FULL_SIDE + x + QR_QUIET_ZONE;
            let dark = (quiet[quiet_bit / 8] >> (7 - quiet_bit % 8)) & 1;
            let core_bit = y * QR_CORE_SIDE + x;
            core[core_bit / 8] |= dark << (7 - core_bit % 8);
        }
    }
    core
}

fn assert_rejected_without_output(symbols: &[u8], expected: KitError, sentinel: [u8; FRAME_LEN]) {
    let mut output = sentinel;
    assert_eq!(decode_fallback(symbols, &mut output), Err(expected));
    assert_eq!(output, sentinel);
}

fn rewrite_checksum(frame: &mut [u8; FRAME_LEN]) {
    let mut preimage = Vec::with_capacity(CHECKSUM_DOMAIN.len() + 1 + PREFIX_LEN);
    preimage.extend_from_slice(CHECKSUM_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(&frame[..PREFIX_LEN]);
    let digest = sha256(&preimage);
    frame[PREFIX_LEN..].copy_from_slice(&digest[..FRAME_LEN - PREFIX_LEN]);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (bytes.len() as u64) * 8;
    let mut padded = Vec::with_capacity(bytes.len() + 72);
    padded.extend_from_slice(bytes);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let (blocks, remainder) = padded.as_slice().as_chunks::<64>();
    assert!(remainder.is_empty(), "SHA-256 block geometry");
    for block in blocks {
        let mut words = [0u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(
                block[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("four-byte word"),
            );
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (&constant, &word) in K.iter().zip(words.iter()) {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(constant)
                .wrapping_add(word);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];
    }

    let mut digest = [0u8; 32];
    let (outputs, remainder) = digest.as_mut_slice().as_chunks_mut::<4>();
    assert!(remainder.is_empty(), "SHA-256 digest geometry");
    for (word, output) in state.iter().zip(outputs.iter_mut()) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    digest
}
