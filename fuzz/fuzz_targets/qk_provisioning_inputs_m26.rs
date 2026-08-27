#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_provisioning::{HostProvisioningRun, ProvisioningArtifacts, ProvisioningError};

const MAX_PRESENTED_BYTES: usize = 1_024;
const FIXED_NONCE: [u8; 12] = [0x26; 12];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Rejected(ProvisioningError),
    Ready(ProvisioningArtifacts),
    NonceState {
        first: ProvisioningArtifacts,
        second: ProvisioningError,
        fresh: ProvisioningArtifacts,
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

fn record(seed: u8, optional: bool) -> Vec<u8> {
    let mut output = vec![1u8];
    let count = if optional { 4u8 } else { 3u8 };
    for tag in 1..=count {
        output.push(tag);
        output.extend_from_slice(&32u16.to_be_bytes());
        output.extend(core::iter::repeat_n(seed.wrapping_add(tag), 32));
    }
    output
}

fn records() -> [Vec<u8>; 4] {
    [
        record(0x11, false),
        record(0x31, true),
        record(0x51, false),
        record(0x71, true),
    ]
}

fn transcripts() -> [Vec<u8>; 4] {
    [
        vec![b'1'; 100],
        vec![b'2'; 100],
        vec![b'3'; 100],
        vec![b'4'; 100],
    ]
}

fn finish(result: Result<HostProvisioningRun, ProvisioningError>) -> Outcome {
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

fn qkec(records: &[Vec<u8>; 4], ceremony_id: &[u8; 16]) -> Outcome {
    finish(HostProvisioningRun::from_qkec(
        [&records[0], &records[1], &records[2], &records[3]],
        ceremony_id,
    ))
}

fn dice(values: &[Vec<u8>; 4]) -> Outcome {
    finish(HostProvisioningRun::from_dice([
        &values[0], &values[1], &values[2], &values[3],
    ]))
}

fn raw_qkec(data: &[u8]) -> Outcome {
    let mut values = records();
    let slot = usize::from(data.get(1).copied().unwrap_or(0)) % values.len();
    values[slot] = data.get(2..).unwrap_or_default().to_vec();
    qkec(&values, &[0x41; 16])
}

fn qkec_scenario(data: &[u8]) -> Outcome {
    let mut values = records();
    match data.get(1).copied().unwrap_or(0) % 10 {
        0 => {}
        1 => {
            values[0].pop();
        }
        2 => values[0][0] = 2,
        3 => values[0][1] = 5,
        4 => values[0][36] = 1,
        5 => {
            values[0][1] = 2;
            values[0][36] = 1;
        }
        6 => {
            values[0][2] = 0;
            values[0][3] = 31;
        }
        7 => values[0][71] = 4,
        8 => values[1] = values[0].clone(),
        9 => {
            values[0] = record(0x11, true);
            values[2] = record(0x51, true);
        }
        _ => unreachable!("modulo ten is exhaustive"),
    }
    let mut ceremony_id = [0x42; 16];
    for (slot, value) in ceremony_id
        .iter_mut()
        .zip(data.get(2..18).unwrap_or_default())
    {
        *slot = *value;
    }
    qkec(&values, &ceremony_id)
}

fn raw_dice(data: &[u8]) -> Outcome {
    let mut values = transcripts();
    let slot = usize::from(data.get(1).copied().unwrap_or(0)) % values.len();
    values[slot] = data.get(2..).unwrap_or_default().to_vec();
    dice(&values)
}

fn dice_scenario(data: &[u8]) -> Outcome {
    let mut values = transcripts();
    match data.get(1).copied().unwrap_or(0) % 12 {
        0 => {}
        1 => {
            values[0].pop();
        }
        2 => values[0].push(b'1'),
        3 => values[0][0] = b'0',
        4 => values[0][50] = b' ',
        5 => values[0][99] = b'7',
        pair @ 6..=11 => {
            const PAIRS: [(usize, usize); 6] = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
            let (left, right) = PAIRS[usize::from(pair - 6)];
            values[right] = values[left].clone();
        }
        _ => unreachable!("modulo twelve is exhaustive"),
    }
    dice(&values)
}

fn nonce_state(data: &[u8]) -> Outcome {
    let values = transcripts();
    let refs = [
        &values[0][..],
        &values[1][..],
        &values[2][..],
        &values[3][..],
    ];
    let mut nonce = FIXED_NONCE;
    for (slot, value) in nonce.iter_mut().zip(data.get(2..14).unwrap_or_default()) {
        *slot = *value;
    }

    let mut run = match HostProvisioningRun::from_dice(refs) {
        Ok(run) => run,
        Err(error) => {
            assert_named_error(error);
            return Outcome::Rejected(error);
        }
    };
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

    let mut fresh_run =
        HostProvisioningRun::from_dice(refs).expect("fresh deterministic public run");
    let fresh = fresh_run
        .encrypt_a1(&nonce)
        .expect("cross-run nonce reuse is deliberately accepted on HOST");
    assert_eq!(fresh, first);
    Outcome::NonceState {
        first,
        second,
        fresh,
    }
}

fn run_once(data: &[u8]) -> Outcome {
    match data.first().copied().unwrap_or(0) % 5 {
        0 => raw_qkec(data),
        1 => qkec_scenario(data),
        2 => raw_dice(data),
        3 => dice_scenario(data),
        4 => nonce_state(data),
        _ => unreachable!("modulo five is exhaustive"),
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
