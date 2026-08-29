#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{derive_change_script_v2, derive_receive_script_v2, parse_descriptor_pair_v2};
use qk_provisioning::{HostProvisioningRunV2, ProvisioningArtifactsV2, ProvisioningError};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_BYTES: usize = 512;
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Rejected(ProvisioningError),
    Complete(ProvisioningArtifactsV2),
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

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each byte is uniquely borrowed and live for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = reference_sha256::Sha256::new();
    hasher
        .update(bytes)
        .expect("bounded public transcript hash");
    hasher
        .finalize()
        .expect("bounded public transcript finalization")
}

fn transcripts(data: &[u8]) -> [[u8; 100]; 4] {
    let mut output = [[b'1'; 100]; 4];
    for (purpose, transcript) in output.iter_mut().enumerate() {
        for (position, symbol) in transcript.iter_mut().enumerate() {
            let fallback = (purpose * 97 + position * 29 + 11) as u8;
            let value = if data.is_empty() {
                fallback
            } else {
                data[(purpose * 100 + position) % data.len()].wrapping_add(fallback)
            };
            *symbol = b'1' + value % 6;
        }
        for symbol in transcript.iter_mut().take(4) {
            *symbol = b'1' + purpose as u8;
        }
    }
    output
}

fn nonce(data: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    for (index, slot) in nonce.iter_mut().enumerate() {
        *slot = data
            .get(index)
            .copied()
            .unwrap_or((index as u8).wrapping_mul(17).wrapping_add(0x44));
    }
    nonce
}

fn polymod_step(pre: u32) -> u32 {
    let high = pre >> 25;
    let mut value = (pre & 0x01ff_ffff) << 5;
    for (bit, generator) in [
        0x3b6a_57b2u32,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ]
    .iter()
    .enumerate()
    {
        if ((high >> bit) & 1) != 0 {
            value ^= generator;
        }
    }
    value
}

fn charset_value(symbol: u8) -> Option<u8> {
    CHARSET
        .iter()
        .position(|candidate| *candidate == symbol)
        .and_then(|position| u8::try_from(position).ok())
}

fn assert_address(address: &[u8; 62], script_pubkey: &[u8; 34]) {
    assert_eq!(&address[..3], b"bc1");
    assert!(address.iter().all(u8::is_ascii));
    let symbols: Vec<u8> = address[3..]
        .iter()
        .map(|symbol| charset_value(*symbol).expect("canonical Bech32 symbol"))
        .collect();
    assert_eq!(symbols.len(), 59);

    let mut polymod = 1u32;
    for value in [3u8, 3, 0, 2, 3] {
        polymod = polymod_step(polymod) ^ u32::from(value);
    }
    for symbol in &symbols {
        polymod = polymod_step(polymod) ^ u32::from(*symbol);
    }
    assert_eq!(polymod, 1);
    assert_eq!(symbols[0], 0);

    let mut program = [0u8; 32];
    let mut accumulator = 0u32;
    let mut bits = 0usize;
    let mut written = 0usize;
    for symbol in &symbols[1..53] {
        accumulator = (accumulator << 5) | u32::from(*symbol);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            program[written] = ((accumulator >> bits) & 0xff) as u8;
            written += 1;
        }
    }
    assert_eq!(written, 32);
    assert_eq!(bits, 4);
    assert_eq!(accumulator & 0x0f, 0);
    assert_eq!(&script_pubkey[..2], &[0x00, 0x20]);
    assert_eq!(&script_pubkey[2..], &program);
}

fn assert_artifacts(
    artifacts: &ProvisioningArtifactsV2,
    transcripts: &[[u8; 100]; 4],
    nonce: &[u8; 12],
) {
    for xpub in &artifacts.account_xpubs {
        assert!(xpub.starts_with(b"xpub"));
        assert!(xpub.iter().all(u8::is_ascii));
    }
    assert_ne!(artifacts.account_xpubs[0], artifacts.account_xpubs[1]);

    let pair = parse_descriptor_pair_v2(&artifacts.descriptors[0], &artifacts.descriptors[1])
        .expect("slice-4 descriptors must strictly reparse as v2");
    assert_eq!(pair.wallet_id(), artifacts.wallet_id);
    let receive = derive_receive_script_v2(&pair, 0).expect("first v2 receive derivation");
    let change = derive_change_script_v2(&pair, 0).expect("first v2 change derivation");
    assert_eq!(receive.script_pubkey, artifacts.first_scripts[0]);
    assert_eq!(change.script_pubkey, artifacts.first_scripts[1]);
    assert_address(&artifacts.first_addresses[0], &receive.script_pubkey);
    assert_address(&artifacts.first_addresses[1], &change.script_pubkey);

    assert_eq!(&artifacts.a1_capsule[..7], b"QKA1\x01\x01\x01");
    assert_eq!(&artifacts.a1_capsule[7..19], nonce);
    let seed_a = sha256(&transcripts[0]);
    let a2 = sha256(&transcripts[3]);
    let mut opened = [0xa5; 32];
    qk_a1::decrypt(
        &a2,
        &artifacts.wallet_id,
        &artifacts.a1_capsule,
        &mut opened,
    )
    .expect("slice-4 capsule must authenticate under dice-derived A2");
    assert_eq!(opened, seed_a);
    wipe(&mut opened);
}

fn run_once(data: &[u8]) -> Outcome {
    let transcripts = transcripts(data);
    let refs = [
        &transcripts[0][..],
        &transcripts[1][..],
        &transcripts[2][..],
        &transcripts[3][..],
    ];
    let mut run = match HostProvisioningRunV2::from_manual_dice(refs) {
        Ok(run) => run,
        Err(error) => {
            assert_named_error(error);
            return Outcome::Rejected(error);
        }
    };
    let nonce = nonce(data);
    let artifacts = match run.encrypt_a1(&nonce) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            assert_named_error(error);
            return Outcome::Rejected(error);
        }
    };
    assert_artifacts(&artifacts, &transcripts, &nonce);
    assert_eq!(
        run.encrypt_a1(&nonce),
        Err(ProvisioningError::NonceReuse),
        "a completed v2 run must never emit a second public artifact"
    );
    Outcome::Complete(artifacts)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = run_once(data);
    let second = run_once(data);
    assert_eq!(first, second);
});
