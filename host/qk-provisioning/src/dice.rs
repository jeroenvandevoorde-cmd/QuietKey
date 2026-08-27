//! Exact four-secret Advanced-mode dice transcript handling.

use crate::secret::{wipe, Secret};
use crate::sha256::sha256;
use crate::ProvisioningError;

const TRANSCRIPT_BYTES: usize = 100;

fn digest_transcript(input: &[u8]) -> Result<Secret<32>, ProvisioningError> {
    let mut stored = [0u8; TRANSCRIPT_BYTES];
    for (position, &byte) in input.iter().enumerate() {
        if position >= TRANSCRIPT_BYTES {
            wipe(&mut stored);
            return Err(ProvisioningError::DiceCount);
        }
        if !(b'1'..=b'6').contains(&byte) {
            wipe(&mut stored);
            return Err(ProvisioningError::InvalidDiceSymbol);
        }
        stored[position] = byte;
    }
    if input.len() != TRANSCRIPT_BYTES {
        wipe(&mut stored);
        return Err(ProvisioningError::DiceCount);
    }
    let mut digest = sha256(&stored);
    wipe(&mut stored);
    Ok(Secret::take(&mut digest))
}

pub(crate) fn digest_four(transcripts: [&[u8]; 4]) -> Result<[Secret<32>; 4], ProvisioningError> {
    let digests = [
        digest_transcript(transcripts[0])?,
        digest_transcript(transcripts[1])?,
        digest_transcript(transcripts[2])?,
        digest_transcript(transcripts[3])?,
    ];
    for left in 0..transcripts.len() {
        for right in left + 1..transcripts.len() {
            if transcripts[left] == transcripts[right] {
                return Err(ProvisioningError::TranscriptReuse);
            }
        }
    }
    Ok(digests)
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
        let mut invalid_overflow = [b'1'; 101];
        invalid_overflow[100] = b'0';
        assert!(matches!(
            digest_transcript(&invalid_overflow),
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

    #[test]
    fn malformed_transcript_precedes_cross_purpose_reuse() {
        let invalid = [b'0'; 100];
        assert!(matches!(
            digest_four([&invalid, &invalid, &[b'2'; 100], &[b'3'; 100]]),
            Err(ProvisioningError::InvalidDiceSymbol)
        ));
        let short = [b'1'; 99];
        assert!(matches!(
            digest_four([&short, &short, &[b'2'; 100], &[b'3'; 100]]),
            Err(ProvisioningError::DiceCount)
        ));
    }
}
