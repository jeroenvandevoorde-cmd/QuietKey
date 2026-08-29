#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_provisioning::{HostProvisioningRunV2, ProvisioningArtifactsV2, ProvisioningError};

const MAX_PRESENTED_BYTES: usize = 1_024;
const FIXED_NONCE: [u8; 12] = *b"QKV2S4NONCE1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Rejected(ProvisioningError),
    Ready(ProvisioningArtifactsV2),
    NonceState {
        first: ProvisioningArtifactsV2,
        second: ProvisioningError,
        fresh: ProvisioningArtifactsV2,
    },
}

fn assert_named_error(error: ProvisioningError) {
    match error {
        ProvisioningError::InvalidRecordLength
        | ProvisioningError::UnsupportedRecordVersion
        | ProvisioningError::UnknownSource
        | ProvisioningError::SourceOutOfOrder
        | ProvisioningError::DuplicateSource
        | ProvisioningError::InvalidSourceLength
        | ProvisioningError::MissingRequiredSource
        | ProvisioningError::SourceSetReuse
        | ProvisioningError::InvalidDiceSymbol
        | ProvisioningError::DiceCount
        | ProvisioningError::TranscriptReuse
        | ProvisioningError::InvalidMasterScalar
        | ProvisioningError::InvalidChildTweak
        | ProvisioningError::ZeroChild
        | ProvisioningError::CryptographicBackend
        | ProvisioningError::CryptographicInvariant
        | ProvisioningError::GeneratedDescriptorInvalid
        | ProvisioningError::NonceReuse
        | ProvisioningError::AlreadyEncrypted => {}
    }
    let rendered = error.to_string();
    assert!(!rendered.is_empty());
    assert!(rendered.is_ascii());
    assert!(rendered.len() < 96);
}

fn expected_input_error(values: &[Vec<u8>; 4]) -> Option<ProvisioningError> {
    for transcript in values {
        for (position, &byte) in transcript.iter().enumerate() {
            if position >= 100 {
                return Some(ProvisioningError::DiceCount);
            }
            if !(b'1'..=b'6').contains(&byte) {
                return Some(ProvisioningError::InvalidDiceSymbol);
            }
        }
        if transcript.len() != 100 {
            return Some(ProvisioningError::DiceCount);
        }
    }
    for left in 0..values.len() {
        for right in left + 1..values.len() {
            if values[left] == values[right] {
                return Some(ProvisioningError::TranscriptReuse);
            }
        }
    }
    None
}

fn transcripts() -> [Vec<u8>; 4] {
    [
        vec![b'1'; 100],
        vec![b'2'; 100],
        vec![b'3'; 100],
        vec![b'4'; 100],
    ]
}

fn construct(values: &[Vec<u8>; 4]) -> Result<HostProvisioningRunV2, ProvisioningError> {
    HostProvisioningRunV2::from_manual_dice([&values[0], &values[1], &values[2], &values[3]])
}

fn finish(result: Result<HostProvisioningRunV2, ProvisioningError>) -> Outcome {
    match result {
        Err(error) => {
            assert_named_error(error);
            Outcome::Rejected(error)
        }
        Ok(mut run) => match run.encrypt_a1(&FIXED_NONCE) {
            Ok(artifacts) => Outcome::Ready(artifacts),
            Err(error) => {
                assert_named_error(error);
                Outcome::Rejected(error)
            }
        },
    }
}

fn raw_transcript(data: &[u8]) -> Outcome {
    let mut values = transcripts();
    let slot = usize::from(data.get(1).copied().unwrap_or(0)) % values.len();
    values[slot] = data.get(2..).unwrap_or_default().to_vec();
    let expected = expected_input_error(&values);
    let outcome = finish(construct(&values));
    match expected {
        Some(error) => assert_eq!(outcome, Outcome::Rejected(error)),
        None => match outcome {
            Outcome::Ready(_) => {}
            Outcome::Rejected(
                ProvisioningError::InvalidMasterScalar
                | ProvisioningError::InvalidChildTweak
                | ProvisioningError::ZeroChild
                | ProvisioningError::CryptographicBackend
                | ProvisioningError::CryptographicInvariant
                | ProvisioningError::GeneratedDescriptorInvalid,
            ) => {}
            _ => panic!("valid transcript reached a wrong outcome category"),
        },
    }
    outcome
}

fn exact_scenario(data: &[u8]) -> Outcome {
    let mut values = transcripts();
    let scenario = data.get(1).copied().unwrap_or(0) % 17;
    let expected = match scenario {
        0 => None,
        1 | 2 | 15 => Some(ProvisioningError::DiceCount),
        3..=5 | 16 => Some(ProvisioningError::InvalidDiceSymbol),
        6..=14 => Some(ProvisioningError::TranscriptReuse),
        _ => unreachable!("modulo seventeen is exhaustive"),
    };
    match scenario {
        0 => {}
        1 => {
            values[0].pop();
        }
        2 => values[0].push(b'1'),
        3 => values[0][0] = b'0',
        4 => values[1][50] = b' ',
        5 => values[3][99] = b'7',
        pair @ 6..=11 => {
            const PAIRS: [(usize, usize); 6] = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
            let (left, right) = PAIRS[usize::from(pair - 6)];
            values[right] = values[left].clone();
        }
        12 => {
            values[1] = values[0].clone();
            values[2] = values[0].clone();
        }
        13 => {
            values[1] = values[0].clone();
            values[3] = values[2].clone();
        }
        14 => {
            values[1] = values[0].clone();
            values[2] = values[0].clone();
            values[3] = values[0].clone();
        }
        15 => {
            values[1] = values[0].clone();
            values[3].pop();
        }
        16 => {
            values[1] = values[0].clone();
            values[3][99] = b'0';
        }
        _ => unreachable!("modulo seventeen is exhaustive"),
    }
    let outcome = finish(construct(&values));
    match expected {
        Some(error) => assert_eq!(outcome, Outcome::Rejected(error)),
        None => assert!(matches!(outcome, Outcome::Ready(_))),
    }
    outcome
}

fn nonce_state(data: &[u8]) -> Outcome {
    let values = transcripts();
    let mut nonce = FIXED_NONCE;
    for (slot, value) in nonce.iter_mut().zip(data.get(2..14).unwrap_or_default()) {
        *slot = *value;
    }
    let mut run = construct(&values).expect("fixed public transcripts must construct");
    let first = run
        .encrypt_a1(&nonce)
        .expect("fixed public transcripts must encrypt once");
    let mut second_nonce = nonce;
    if data.get(1).copied().unwrap_or(0) & 1 != 0 {
        second_nonce[11] ^= 1;
    }
    let expected = if second_nonce == nonce {
        ProvisioningError::NonceReuse
    } else {
        ProvisioningError::AlreadyEncrypted
    };
    let second = run
        .encrypt_a1(&second_nonce)
        .expect_err("a second same-run encryption must reject");
    assert_eq!(second, expected);
    assert_named_error(second);

    let mut fresh_run = construct(&values).expect("fresh public run");
    let fresh = fresh_run
        .encrypt_a1(&nonce)
        .expect("HOST accepts a caller's nonce in a fresh run");
    assert_eq!(fresh, first);
    Outcome::NonceState {
        first,
        second,
        fresh,
    }
}

fn run_once(data: &[u8]) -> Outcome {
    match data.first().copied().unwrap_or(0) % 3 {
        0 => raw_transcript(data),
        1 => exact_scenario(data),
        2 => nonce_state(data),
        _ => unreachable!("modulo three is exhaustive"),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = run_once(data);
    let second = run_once(data);
    assert_eq!(first, second);
});
