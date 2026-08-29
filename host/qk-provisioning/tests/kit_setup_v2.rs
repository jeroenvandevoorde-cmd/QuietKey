//! Exact v2 slice-8 seam over the two registered public GOLDEN fixtures.

use qk_kit::{combine_frames, decode_fallback, FrameMetadata, QrMetadata, ShareIndex};
use qk_provisioning::{
    HostProvisioningRunV2, KitCopyV2, KitPageDispositionV2, KitSetupReceiptV2, KitShareIndexV2,
    ProvisioningError,
};
use std::collections::BTreeMap;

const PROVISIONING_FIXTURE: &str = include_str!("fixtures/provisioning_v2.txt");
const KIT_FIXTURE: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");

fn fields(text: &'static str) -> BTreeMap<&'static str, &'static str> {
    let mut fields = BTreeMap::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").expect("framed public fact");
        assert!(fields.insert(name, value).is_none(), "unique field {name}");
    }
    fields
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
        *slot = u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex");
    }
    output
}

fn transcripts() -> [[u8; 100]; 4] {
    let facts = fields(PROVISIONING_FIXTURE);
    [
        facts["seed_a_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("Seed-A transcript"),
        facts["signer_b_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("Signer-B transcript"),
        facts["kit_r_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("Kit-R transcript"),
        facts["a2_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("A2 transcript"),
    ]
}

fn run() -> HostProvisioningRunV2 {
    let values = transcripts();
    HostProvisioningRunV2::from_manual_dice([&values[0], &values[1], &values[2], &values[3]])
        .expect("registered public transcripts")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedPage {
    copy: KitCopyV2,
    share_index: KitShareIndexV2,
    wallet_id: [u8; 32],
    qr_metadata: QrMetadata,
    fallback: [u8; 228],
    qr: [u8; 529],
}

fn capture_all() -> (KitSetupReceiptV2, Vec<CapturedPage>) {
    let facts = fields(PROVISIONING_FIXTURE);
    let mut run = run();
    run.encrypt_a1(&hex_array(facts["a1_nonce_hex"]))
        .expect("registered A1");
    let mut pages = Vec::new();
    let receipt = run
        .emit_two_kit_copies(|page| {
            let mut fallback = [0u8; 228];
            for line in 0..4 {
                fallback[line * 57..(line + 1) * 57]
                    .copy_from_slice(page.fallback_line(line).expect("four fixed lines"));
            }
            assert!(page.fallback_line(4).is_none());
            pages.push(CapturedPage {
                copy: page.copy(),
                share_index: page.share_index(),
                wallet_id: *page.wallet_id(),
                qr_metadata: page.qr_metadata(),
                fallback,
                qr: *page.qr_packed(),
            });
            KitPageDispositionV2::Accepted
        })
        .expect("four accepted page views");
    (receipt, pages)
}

#[test]
fn exact_two_copy_sequence_matches_every_registered_codec_fact() {
    let fixture = fields(KIT_FIXTURE);
    let wallet_id = hex_array::<32>(fixture["wallet_id_hex"]);
    let (receipt, pages) = capture_all();
    assert_eq!(receipt.wallet_id(), wallet_id);
    assert_eq!(receipt.copy_count(), 2);
    assert_eq!(receipt.page_count(), 4);
    assert_eq!(pages.len(), 4);
    assert_eq!(
        pages
            .iter()
            .map(|page| (page.copy, page.share_index))
            .collect::<Vec<_>>(),
        [
            (KitCopyV2::One, KitShareIndexV2::One),
            (KitCopyV2::One, KitShareIndexV2::Two),
            (KitCopyV2::Two, KitShareIndexV2::One),
            (KitCopyV2::Two, KitShareIndexV2::Two),
        ]
    );

    for (page_number, page) in pages.iter().enumerate() {
        let share_number = if page.share_index == KitShareIndexV2::One {
            1
        } else {
            2
        };
        assert_eq!(page.wallet_id, wallet_id);
        assert_eq!(
            page.fallback.as_slice(),
            fixture[&*format!("fallback_{share_number}_ascii")].as_bytes()
        );
        assert_eq!(
            page.qr,
            hex_array(fixture[&*format!("qr_{share_number}_quiet_packed_hex")])
        );
        assert_eq!(
            page.qr_metadata.mask.to_string(),
            fixture[&*format!("qr_{share_number}_mask")]
        );
        let expected_penalties: Vec<u32> = fixture[&*format!("qr_{share_number}_penalties")]
            .split(',')
            .map(|value| value.parse().expect("penalty"))
            .collect();
        assert_eq!(page.qr_metadata.penalties.as_slice(), expected_penalties);

        let mut frame = [0u8; 142];
        let codec_index = if share_number == 1 {
            ShareIndex::One
        } else {
            ShareIndex::Two
        };
        assert_eq!(
            decode_fallback(&page.fallback, &mut frame),
            Ok(FrameMetadata {
                share_index: codec_index,
                wallet_id,
            }),
            "page {page_number} fallback"
        );
        assert_eq!(
            frame,
            hex_array(fixture[&*format!("frame_{share_number}_hex")])
        );
    }

    assert_eq!(pages[0].fallback, pages[2].fallback);
    assert_eq!(pages[0].qr, pages[2].qr);
    assert_eq!(pages[1].fallback, pages[3].fallback);
    assert_eq!(pages[1].qr, pages[3].qr);
}

#[test]
fn all_four_cross_copy_pairings_recover_the_registered_payload_identity() {
    let fixture = fields(KIT_FIXTURE);
    let (_, pages) = capture_all();
    let mut frames = [[0u8; 142]; 4];
    for (output, page) in frames.iter_mut().zip(&pages) {
        decode_fallback(&page.fallback, output).expect("complete page fallback");
    }
    for one in [0usize, 2] {
        for two in [1usize, 3] {
            let combined = combine_frames(&frames[one], &frames[two]);
            assert!(combined.is_ok(), "valid cross pairing {one}+{two}");
            drop(combined);
        }
    }

    let share_one = hex_array::<96>(fixture["share_1_hex"]);
    let share_two = hex_array::<96>(fixture["share_2_hex"]);
    let expected_payload = hex_array::<96>(fixture["owned_payload_hex"]);
    let recovered = core::array::from_fn(|index| share_one[index] ^ share_two[index]);
    assert_eq!(recovered, expected_payload);
    assert_eq!(&frames[0][38..134], &share_one);
    assert_eq!(&frames[1][38..134], &share_two);
}

#[test]
fn a1_gate_and_each_first_rejection_stop_are_named_and_receipt_free() {
    let mut calls = 0usize;
    assert_eq!(
        run().emit_two_kit_copies(|_| {
            calls += 1;
            KitPageDispositionV2::Accepted
        }),
        Err(ProvisioningError::A1NotReady)
    );
    assert_eq!(calls, 0);

    let facts = fields(PROVISIONING_FIXTURE);
    let nonce = hex_array::<12>(facts["a1_nonce_hex"]);
    for reject_at in 0..4 {
        let mut run = run();
        run.encrypt_a1(&nonce).expect("A1 gate");
        let mut seen = Vec::new();
        assert_eq!(
            run.emit_two_kit_copies(|page| {
                seen.push((page.copy(), page.share_index()));
                if seen.len() - 1 == reject_at {
                    KitPageDispositionV2::Rejected
                } else {
                    KitPageDispositionV2::Accepted
                }
            }),
            Err(ProvisioningError::PrintRejected)
        );
        assert_eq!(seen.len(), reject_at + 1);
    }
}
