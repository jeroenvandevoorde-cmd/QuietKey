//! Private exact BIP-380 descriptor-checksum verification.

const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChecksumFixtureError {
    MissingChecksum,
    InvalidChecksumLength,
    InvalidChecksumCharacter,
    InvalidDescriptorCharacter,
    ChecksumMismatch,
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

fn charset_position(charset: &[u8], byte: u8) -> Option<u8> {
    charset
        .iter()
        .position(|&candidate| candidate == byte)
        .and_then(|position| u8::try_from(position).ok())
}

pub(crate) fn is_checksum_character(byte: u8) -> bool {
    charset_position(CHECKSUM_CHARSET, byte).is_some()
}

pub(crate) fn is_descriptor_character(byte: u8) -> bool {
    charset_position(INPUT_CHARSET, byte).is_some()
}

fn descriptor_polymod(body: &[u8], checksum: &[u8]) -> Option<u64> {
    let mut state = 1u64;
    let mut class = 0u8;
    let mut class_count = 0u8;
    for &byte in body {
        let position = charset_position(INPUT_CHARSET, byte)?;
        state = polymod(state, position & 31);
        class = class.saturating_mul(3).saturating_add(position >> 5);
        class_count = class_count.saturating_add(1);
        if class_count == 3 {
            state = polymod(state, class);
            class = 0;
            class_count = 0;
        }
    }
    if class_count != 0 {
        state = polymod(state, class);
    }
    for &byte in checksum {
        state = polymod(state, charset_position(CHECKSUM_CHARSET, byte)?);
    }
    Some(state)
}

pub(crate) fn descriptor_checksum_matches(body: &[u8], checksum: &[u8]) -> bool {
    descriptor_polymod(body, checksum) == Some(1)
}

#[cfg(test)]
fn verify_fixture_token(input: &[u8]) -> Result<(), ChecksumFixtureError> {
    if !input.contains(&b'#') {
        return Err(ChecksumFixtureError::MissingChecksum);
    }
    if input.len() < 9 || input[input.len() - 9] != b'#' {
        return Err(ChecksumFixtureError::InvalidChecksumLength);
    }
    let body = &input[..input.len() - 9];
    let checksum = &input[input.len() - 8..];
    if checksum.iter().any(|&byte| !is_checksum_character(byte)) {
        return Err(ChecksumFixtureError::InvalidChecksumCharacter);
    }
    if body.iter().any(|&byte| !is_descriptor_character(byte)) {
        return Err(ChecksumFixtureError::InvalidDescriptorCharacter);
    }
    if !descriptor_checksum_matches(body, checksum) {
        return Err(ChecksumFixtureError::ChecksumMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{verify_fixture_token, ChecksumFixtureError, INPUT_CHARSET};

    const VECTORS: &str = include_str!("../tests/fixtures/bip380_checksum_vectors.txt");

    fn expected(value: &str) -> Result<(), ChecksumFixtureError> {
        match value {
            "accept" => Ok(()),
            "MissingChecksum" => Err(ChecksumFixtureError::MissingChecksum),
            "InvalidChecksumLength" => Err(ChecksumFixtureError::InvalidChecksumLength),
            "ChecksumMismatch" => Err(ChecksumFixtureError::ChecksumMismatch),
            "InvalidChecksumCharacter" => Err(ChecksumFixtureError::InvalidChecksumCharacter),
            "InvalidDescriptorCharacter" => Err(ChecksumFixtureError::InvalidDescriptorCharacter),
            _ => panic!("unknown checksum fixture category"),
        }
    }

    #[test]
    fn complete_bip380_checksum_inventory_passes_without_skip() {
        assert_eq!(VECTORS.len(), 1_310);
        assert!(VECTORS.ends_with('\n'));
        assert!(!VECTORS.contains('\r'));
        let fields: Vec<&str> = VECTORS
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert_eq!(fields.len(), 8 * 4);
        for block in fields.chunks_exact(4) {
            assert!(block[0].starts_with("case: "));
            assert!(block[1].starts_with("source_line: "));
            let token = block[2].strip_prefix("token: ").expect("token field");
            let category = block[3].strip_prefix("expected: ").expect("expected field");
            assert_eq!(
                verify_fixture_token(token.as_bytes()),
                expected(category),
                "{}",
                block[0]
            );
        }
    }

    #[test]
    fn input_charset_tail_and_checksum_mapping_match_bip380() {
        assert_eq!(INPUT_CHARSET.len(), 95);
        assert_eq!(&INPUT_CHARSET[90..], b"`#\"\\ ");
        assert_eq!(verify_fixture_token(b"raw(`\"\\ )#n50qjjqa"), Ok(()));
    }
}
