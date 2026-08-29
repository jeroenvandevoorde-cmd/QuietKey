#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_kit::{encode_qr, QrMetadata, QR_PACKED_BYTES, QR_SIZE};
use qk_provisioning::{
    HostProvisioningRunV2, KitCopyV2, KitPageDispositionV2, KitSetupErrorV2, KitShareIndexV2,
    ProvisioningError,
};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_BYTES: usize = 512;
const FRAME_LEN: usize = 142;
const SHARE_OFFSET: usize = 38;
const SHARE_LEN: usize = 96;
const CHECKSUM_OFFSET: usize = 134;
const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const CHECKSUM_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";
const FIXED_NONCE: [u8; 12] = *b"QKV2S8NONCE1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageFact {
    copy: KitCopyV2,
    share_index: KitShareIndexV2,
    wallet_id: [u8; 32],
    fallback_sha256: [u8; 32],
    qr_sha256: [u8; 32],
    qr_metadata: QrMetadata,
}

const EMPTY_PAGE: PageFact = PageFact {
    copy: KitCopyV2::One,
    share_index: KitShareIndexV2::One,
    wallet_id: [0u8; 32],
    fallback_sha256: [0u8; 32],
    qr_sha256: [0u8; 32],
    qr_metadata: QrMetadata {
        mask: 0,
        penalties: [0u32; 8],
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SetupSummary {
    result: Result<([u8; 32], u8, u8), KitSetupErrorV2>,
    seen: u8,
    pages: [PageFact; 4],
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each byte is uniquely borrowed and live for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = reference_sha256::Sha256::new();
    for part in parts {
        hasher.update(part).expect("bounded reference input");
    }
    hasher.finalize().expect("bounded reference digest")
}

fn selector(data: &[u8]) -> u8 {
    data.iter()
        .fold(0x6du8, |state, byte| state.wrapping_mul(33) ^ byte)
}

fn transcripts(data: &[u8]) -> [[u8; 100]; 4] {
    let mut transcripts = [[b'1'; 100]; 4];
    for (purpose, transcript) in transcripts.iter_mut().enumerate() {
        for (position, symbol) in transcript.iter_mut().enumerate() {
            let source = data
                .get((purpose * 100 + position) % data.len().max(1))
                .copied()
                .unwrap_or((purpose * 67 + position * 29) as u8);
            *symbol = b'1' + source.wrapping_add((purpose * 17 + position) as u8) % 6;
        }
        for symbol in transcript.iter_mut().take(4) {
            *symbol = b'1' + purpose as u8;
        }
    }
    transcripts
}

fn nonce(data: &[u8]) -> [u8; 12] {
    let mut nonce = FIXED_NONCE;
    for (slot, byte) in nonce.iter_mut().zip(data.iter().rev()) {
        *slot ^= *byte;
    }
    nonce
}

fn alphabet_value(symbol: u8) -> u8 {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .expect("generation emits only canonical fallback symbols") as u8
}

fn decode_fallback(symbols: &[u8; 228]) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    let mut final_value = 0u8;
    for (symbol_index, symbol) in symbols.iter().enumerate() {
        let value = alphabet_value(*symbol);
        if symbol_index + 1 == symbols.len() {
            final_value = value;
        }
        for symbol_bit in 0..5 {
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index >= FRAME_LEN * 8 {
                break;
            }
            frame[bit_index / 8] |= ((value >> (4 - symbol_bit)) & 1) << (7 - bit_index % 8);
        }
    }
    assert_eq!(final_value & 0x0f, 0);
    frame
}

fn assert_frame(frame: &[u8; FRAME_LEN], expected_index: KitShareIndexV2, wallet_id: &[u8; 32]) {
    assert_eq!(&frame[..4], b"QKKS");
    assert_eq!(frame[4], 1);
    assert_eq!(
        frame[5],
        match expected_index {
            KitShareIndexV2::One => 1,
            KitShareIndexV2::Two => 2,
        }
    );
    assert_eq!(&frame[6..38], wallet_id);
    let digest = sha256(&[CHECKSUM_DOMAIN, &[0], &frame[..CHECKSUM_OFFSET]]);
    assert_eq!(&frame[CHECKSUM_OFFSET..], &digest[..8]);
}

fn assert_qr_geometry(qr: &[u8; QR_PACKED_BYTES]) {
    assert_eq!(qr[QR_PACKED_BYTES - 1] & 0x7f, 0);
    for y in 0..QR_SIZE {
        for x in 0..QR_SIZE {
            if !(4..QR_SIZE - 4).contains(&x) || !(4..QR_SIZE - 4).contains(&y) {
                let bit = y * QR_SIZE + x;
                assert_eq!(qr[bit / 8] & (1 << (7 - bit % 8)), 0);
            }
        }
    }
}

fn assert_setup_error(error: KitSetupErrorV2) {
    let expected = match error {
        KitSetupErrorV2::A1NotReady => "A1NotReady",
        KitSetupErrorV2::KitEncodingInvariant => "KitEncodingInvariant",
        KitSetupErrorV2::PrintRejected => "PrintRejected",
    };
    assert_eq!(error.to_string(), expected);
}

fn run_setup(data: &[u8], scenario: u8) -> SetupSummary {
    let transcripts = transcripts(data);
    let refs = [
        &transcripts[0][..],
        &transcripts[1][..],
        &transcripts[2][..],
        &transcripts[3][..],
    ];
    let mut run = HostProvisioningRunV2::from_manual_dice(refs)
        .expect("fuzz constructor makes four valid distinct transcripts");
    let expected_payload = [
        sha256(&[&transcripts[0]]),
        sha256(&[&transcripts[1]]),
        sha256(&[&transcripts[3]]),
    ]
    .concat();

    if scenario != 0 {
        run.encrypt_a1(&nonce(data)).expect("one generated A1");
    }
    let reject_at = match scenario {
        1..=4 => Some(usize::from(scenario - 1)),
        _ => None,
    };
    let mut pages = [EMPTY_PAGE; 4];
    let mut seen = 0usize;
    let mut first_shares = [[0u8; SHARE_LEN]; 2];
    let mut first_share_seen = [false; 2];

    let result = run.emit_two_kit_copies(|page| {
        let expected_order = [
            (KitCopyV2::One, KitShareIndexV2::One),
            (KitCopyV2::One, KitShareIndexV2::Two),
            (KitCopyV2::Two, KitShareIndexV2::One),
            (KitCopyV2::Two, KitShareIndexV2::Two),
        ];
        assert!(seen < expected_order.len());
        assert_eq!((page.copy(), page.share_index()), expected_order[seen]);
        assert!(page.fallback_line(4).is_none());

        let mut fallback = [0u8; 228];
        for line in 0..4 {
            fallback[line * 57..(line + 1) * 57]
                .copy_from_slice(page.fallback_line(line).expect("fixed line geometry"));
        }
        let mut frame = decode_fallback(&fallback);
        assert_frame(&frame, page.share_index(), page.wallet_id());

        let mut repeated_qr = [0u8; QR_PACKED_BYTES];
        let repeated_metadata = encode_qr(&frame, &mut repeated_qr).expect("generated frame");
        assert_eq!(repeated_metadata, page.qr_metadata());
        assert_eq!(&repeated_qr, page.qr_packed());
        assert_qr_geometry(page.qr_packed());

        let share_slot = usize::from(frame[5] - 1);
        if first_share_seen[share_slot] {
            assert_eq!(
                &frame[SHARE_OFFSET..CHECKSUM_OFFSET],
                &first_shares[share_slot]
            );
        } else {
            first_shares[share_slot].copy_from_slice(&frame[SHARE_OFFSET..CHECKSUM_OFFSET]);
            first_share_seen[share_slot] = true;
        }
        if first_share_seen.iter().all(|value| *value) {
            for index in 0..SHARE_LEN {
                assert_eq!(
                    first_shares[0][index] ^ first_shares[1][index],
                    expected_payload[index]
                );
            }
        }

        pages[seen] = PageFact {
            copy: page.copy(),
            share_index: page.share_index(),
            wallet_id: *page.wallet_id(),
            fallback_sha256: sha256(&[&fallback]),
            qr_sha256: sha256(&[page.qr_packed()]),
            qr_metadata: page.qr_metadata(),
        };
        wipe(&mut fallback);
        wipe(&mut frame);
        wipe(&mut repeated_qr);

        let current = seen;
        seen += 1;
        if reject_at == Some(current) {
            KitPageDispositionV2::Rejected
        } else {
            KitPageDispositionV2::Accepted
        }
    });

    let summary_result = match scenario {
        0 => {
            assert_eq!(result, Err(KitSetupErrorV2::A1NotReady));
            assert_eq!(seen, 0);
            Err(KitSetupErrorV2::A1NotReady)
        }
        1..=4 => {
            assert_eq!(result, Err(KitSetupErrorV2::PrintRejected));
            assert_eq!(seen, usize::from(scenario));
            Err(KitSetupErrorV2::PrintRejected)
        }
        _ => {
            let receipt = result.expect("four accepted pages release one receipt");
            assert_eq!(seen, 4);
            assert_eq!(receipt.copy_count(), 2);
            assert_eq!(receipt.page_count(), 4);
            assert_eq!(receipt.wallet_id(), pages[0].wallet_id);
            Ok((
                receipt.wallet_id(),
                receipt.copy_count(),
                receipt.page_count(),
            ))
        }
    };
    if let Err(error) = summary_result {
        assert_setup_error(error);
    }
    wipe(&mut first_shares[0]);
    wipe(&mut first_shares[1]);
    SetupSummary {
        result: summary_result,
        seen: seen as u8,
        pages,
    }
}

fn fast_rejection() -> ProvisioningError {
    let short = [b'1'; 99];
    let other = [[b'2'; 100], [b'3'; 100], [b'4'; 100]];
    HostProvisioningRunV2::from_manual_dice([&short, &other[0], &other[1], &other[2]])
        .err()
        .expect("99-symbol transcript")
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    if selector(data) != 0 {
        let first = fast_rejection();
        let second = fast_rejection();
        assert_eq!(first, ProvisioningError::DiceCount);
        assert_eq!(first, second);
        assert_eq!(
            first.to_string(),
            "dice transcript must contain exactly 100 symbols"
        );
        return;
    }

    let scenario = data.first().copied().unwrap_or(0) % 6;
    let first = run_setup(data, scenario);
    let second = run_setup(data, scenario);
    assert_eq!(first, second);
});
