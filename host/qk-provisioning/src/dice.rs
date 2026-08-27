//! Exact four-secret Advanced-mode dice transcript handling.

use crate::secret::Secret;
use crate::sha256::sha256;
use crate::ProvisioningError;

const TRANSCRIPT_BYTES: usize = 100;

fn digest_transcript(input: &[u8]) -> Result<Secret<32>, ProvisioningError> {
    let mut stored = [0u8; TRANSCRIPT_BYTES];
    for (position, &byte) in input.iter().enumerate() {
        if !(b'1'..=b'6').contains(&byte) {
            stored.fill(0);
            return Err(ProvisioningError::InvalidDiceSymbol);
        }
        if position >= TRANSCRIPT_BYTES {
            stored.fill(0);
            return Err(ProvisioningError::DiceCount);
        }
        stored[position] = byte;
    }
    if input.len() != TRANSCRIPT_BYTES {
        stored.fill(0);
        return Err(ProvisioningError::DiceCount);
    }
    let digest = sha256(&stored);
    stored.fill(0);
    Ok(Secret::new(digest))
}

pub(crate) fn digest_four(transcripts: [&[u8]; 4]) -> Result<[Secret<32>; 4], ProvisioningError> {
    for left in 0..transcripts.len() {
        for right in left + 1..transcripts.len() {
            if transcripts[left] == transcripts[right] {
                return Err(ProvisioningError::TranscriptReuse);
            }
        }
    }
    Ok([
        digest_transcript(transcripts[0])?,
        digest_transcript(transcripts[1])?,
        digest_transcript(transcripts[2])?,
        digest_transcript(transcripts[3])?,
    ])
}

#[cfg(test)]
mod tests {
    use super::{digest_four, digest_transcript};
    use crate::ProvisioningError;

    #[test]
    fn count_and_symbol_failures_are_distinct() {
        assert!(matches!(
            digest_transcript(&[b'1'; 99]),
            Err(ProvisioningError::DiceCount)
        ));
        assert!(matches!(
            digest_transcript(&[b'1'; 101]),
            Err(ProvisioningError::DiceCount)
        ));
        let mut invalid = [b'1'; 100];
        invalid[99] = b'0';
        assert!(matches!(
            digest_transcript(&invalid),
            Err(ProvisioningError::InvalidDiceSymbol)
        ));
    }

    #[test]
    fn all_six_reuse_pairs_reject() {
        let base = [[b'1'; 100], [b'2'; 100], [b'3'; 100], [b'4'; 100]];
        for left in 0..4 {
            for right in left + 1..4 {
                let mut values = base;
                values[right] = values[left];
                assert!(matches!(
                    digest_four([&values[0], &values[1], &values[2], &values[3]]),
                    Err(ProvisioningError::TranscriptReuse)
                ));
            }
        }
    }
}
