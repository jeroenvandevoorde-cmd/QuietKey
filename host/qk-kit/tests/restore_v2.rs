//! Registered end-to-end facts for the two consuming HOST Kit-Restore branches.

use qk_kit::{
    combine_frames, A1ReprintDispositionV2, KitRestoreDispositionV2, KitRestoreErrorV2,
    RecoveredKitPayload, ReplacementBViewV2, SurvivingBFactorV2, FRAME_LEN,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PROVISIONING: &[u8] =
    include_bytes!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &[u8] = include_bytes!("fixtures/kit_share_v2.txt");
const FRESH_REPRINT_NONCE: [u8; 12] = *b"QKV2S10NEW01";

fn field<'fixture>(fixture: &'fixture [u8], name: &str) -> &'fixture str {
    fixture
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = core::str::from_utf8(line).expect("registered fixture is ASCII");
            let (candidate, value) = line.split_once(": ")?;
            (candidate == name).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing registered fixture field {name}"))
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("registered fixture hex is canonical lowercase"),
    }
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2, "registered fixture hex width");
    let mut result = [0u8; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "even fixture hex width");
    for (output, pair) in result.iter_mut().zip(pairs) {
        *output = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    result
}

fn wallet_id() -> [u8; 32] {
    hex_array(field(PROVISIONING, "wallet_id"))
}

fn descriptors() -> [[u8; 306]; 2] {
    [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("registered receive descriptor width"),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .expect("registered change descriptor width"),
    ]
}

fn account_xpubs() -> [[u8; 111]; 2] {
    [
        field(PROVISIONING, "role_a_account_xpub")
            .as_bytes()
            .try_into()
            .expect("registered role-A xpub width"),
        field(PROVISIONING, "role_b_account_xpub")
            .as_bytes()
            .try_into()
            .expect("registered role-B xpub width"),
    ]
}

fn fingerprints() -> [[u8; 4]; 2] {
    [
        hex_array(field(PROVISIONING, "role_a_origin_fingerprint")),
        hex_array(field(PROVISIONING, "role_b_origin_fingerprint")),
    ]
}

fn recovered() -> RecoveredKitPayload {
    let frame_one = hex_array::<FRAME_LEN>(field(KIT_SHARES, "frame_1_hex"));
    let frame_two = hex_array::<FRAME_LEN>(field(KIT_SHARES, "frame_2_hex"));
    combine_frames(&frame_one, &frame_two).expect("registered opposite-index pair")
}

fn bound() -> qk_kit::BoundKitRestoreV2 {
    recovered()
        .bind_restore_v2(&descriptors(), &wallet_id())
        .unwrap_or_else(|error| panic!("registered wallet must rebind: {error}"))
}

fn restore_error<T>(result: Result<T, KitRestoreErrorV2>) -> KitRestoreErrorV2 {
    match result {
        Err(error) => error,
        Ok(value) => {
            drop(value);
            panic!("restore operation unexpectedly succeeded")
        }
    }
}

fn surviving_b(
    wallet: [u8; 32],
    account_xpub: [u8; 111],
    fingerprint: [u8; 4],
    a2: [u8; 32],
) -> SurvivingBFactorV2 {
    let mut caller_a2 = a2;
    let factor = SurvivingBFactorV2::take(wallet, account_xpub, fingerprint, &mut caller_a2);
    assert_eq!(caller_a2, [0u8; 32], "take clears the caller A2 buffer");
    factor
}

#[test]
fn registered_inputs_are_byte_verbatim_and_cross_tied() {
    assert_eq!(PROVISIONING.len(), 9_219);
    assert_eq!(PROVISIONING.last(), Some(&b'\n'));
    assert!(!PROVISIONING.contains(&b'\r'));
    assert_eq!(KIT_SHARES.len(), 14_849);
    assert_eq!(KIT_SHARES.last(), Some(&b'\n'));
    assert!(!KIT_SHARES.contains(&b'\r'));
    assert_eq!(field(KIT_SHARES, "source_provisioning_bytes"), "9219");
    assert_eq!(
        field(KIT_SHARES, "source_provisioning_sha256"),
        "04161895860df1b672e91e3249471dde9564cef13dd72d5b3a45b240e9d79741"
    );
    assert_eq!(
        field(KIT_SHARES, "wallet_id_hex"),
        field(PROVISIONING, "wallet_id")
    );
    assert_eq!(
        field(KIT_SHARES, "owned_payload_hex"),
        field(PROVISIONING, "owned_payload_hex")
    );
    assert_eq!(
        field(KIT_SHARES, "combined_payload_hex"),
        field(PROVISIONING, "owned_payload_hex")
    );
}

#[test]
fn exact_rebind_releases_only_registered_public_wallet_facts() {
    let restored = bound();
    assert_eq!(restored.wallet_id(), wallet_id());
    assert_eq!(restored.account_xpubs(), account_xpubs());
    assert_eq!(restored.origin_fingerprints(), fingerprints());
    drop(restored);

    let mut wrong_wallet = wallet_id();
    wrong_wallet[0] ^= 1;
    assert_eq!(
        restore_error(recovered().bind_restore_v2(&descriptors(), &wrong_wallet)),
        KitRestoreErrorV2::RecoveredWalletMismatch
    );

    let mut wrong_descriptor = descriptors();
    wrong_descriptor[0][0] ^= 1;
    assert_eq!(
        restore_error(recovered().bind_restore_v2(&wrong_descriptor, &wallet_id())),
        KitRestoreErrorV2::RecoveredWalletMismatch
    );

    let mut swapped = descriptors();
    swapped.swap(0, 1);
    assert_eq!(
        restore_error(recovered().bind_restore_v2(&swapped, &wallet_id())),
        KitRestoreErrorV2::RecoveredWalletMismatch
    );
}

#[test]
fn replacement_b_authenticates_surviving_a1_and_returns_exact_role_b_facts() {
    let expected_wallet = wallet_id();
    let expected_xpub = account_xpubs()[1];
    let expected_fingerprint = fingerprints()[1];
    let capsule = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let receipt = bound()
        .prepare_replacement_b(&capsule)
        .expect("registered A1 precondition")
        .complete(|view: ReplacementBViewV2<'_>| {
            assert_eq!(view.wallet_id(), &expected_wallet);
            assert_eq!(view.account_xpub(), &expected_xpub);
            assert_eq!(view.origin_fingerprint(), &expected_fingerprint);
            KitRestoreDispositionV2::Accepted
        })
        .unwrap_or_else(|error| panic!("registered replacement-B path: {error}"));
    assert_eq!(receipt.wallet_id(), expected_wallet);
    assert_eq!(receipt.account_xpub(), expected_xpub);
    assert_eq!(receipt.origin_fingerprint(), expected_fingerprint);

    let error = restore_error(
        bound()
            .prepare_replacement_b(&capsule)
            .expect("registered A1 precondition")
            .complete(|_| KitRestoreDispositionV2::Rejected),
    );
    assert_eq!(error, KitRestoreErrorV2::ReplacementBRejected);
    assert_eq!(error.name(), "ReplacementBRejected");

    let mut changed = capsule;
    changed[31] ^= 1;
    let error = restore_error(bound().prepare_replacement_b(&changed));
    assert_eq!(error, KitRestoreErrorV2::SurvivingA1Mismatch);
    assert_eq!(error.name(), "SurvivingA1Mismatch");
}

#[test]
fn a1_reprint_requires_exact_surviving_b_and_authenticates_scan_back() {
    let expected_wallet = wallet_id();
    let expected_xpub = account_xpubs()[1];
    let expected_fingerprint = fingerprints()[1];
    let seed_a = hex_array::<32>(field(PROVISIONING, "seed_a_transcript_sha256"));
    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    let old_capsule = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let factor = surviving_b(expected_wallet, expected_xpub, expected_fingerprint, a2);
    assert_eq!(factor.wallet_id(), expected_wallet);
    assert_eq!(factor.account_xpub(), expected_xpub);
    assert_eq!(factor.origin_fingerprint(), expected_fingerprint);

    let mut printed = [0u8; 67];
    let receipt = bound()
        .prepare_a1_reprint(factor, &FRESH_REPRINT_NONCE)
        .expect("registered surviving-B precondition")
        .complete(|view, scan_back| {
            printed.copy_from_slice(view.capsule());
            scan_back.copy_from_slice(view.capsule());
            A1ReprintDispositionV2::Accepted
        })
        .unwrap_or_else(|error| panic!("registered A1 reprint path: {error}"));
    assert_ne!(printed, old_capsule, "fresh nonce changes the capsule");
    assert_eq!(receipt.wallet_id(), expected_wallet);
    assert_eq!(receipt.nonce(), FRESH_REPRINT_NONCE);
    assert_eq!(
        receipt.capsule_sha256(),
        hex_array("ea4aed0ce7a38dab3cb95f1887d0b0d3268fa54f277c458017136a7dc69b927c")
    );

    let mut opened = [0xa5; 32];
    assert_eq!(
        qk_a1::decrypt(&a2, &expected_wallet, &printed, &mut opened),
        Ok(())
    );
    assert_eq!(opened, seed_a, "scan-back capsule authenticates Seed-A");
    printed[31] ^= 1;
    opened = [0xa5; 32];
    assert_eq!(
        qk_a1::decrypt(&a2, &expected_wallet, &printed, &mut opened),
        Err(qk_a1::A1Error::AuthenticationFailed)
    );
    assert_eq!(opened, [0xa5; 32], "failed authentication releases nothing");
}

#[cfg(feature = "process-v3")]
#[test]
fn staged_a1_reprint_survives_transport_yield_and_consumes_scan_back() {
    let expected_wallet = wallet_id();
    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    let staged = bound()
        .prepare_a1_reprint(
            surviving_b(expected_wallet, account_xpubs()[1], fingerprints()[1], a2),
            &FRESH_REPRINT_NONCE,
        )
        .expect("registered surviving-B precondition")
        .into_staged();

    let mut printed = [0u8; 67];
    printed.copy_from_slice(staged.capsule());
    let mut scan_back = printed;
    let receipt = staged
        .complete_scan_back(&mut scan_back)
        .expect("exact asynchronous scan-back");
    assert_eq!(scan_back, [0u8; 67], "caller scan-back is consumed");
    assert_eq!(receipt.wallet_id(), expected_wallet);
    assert_eq!(receipt.nonce(), FRESH_REPRINT_NONCE);

    let staged = bound()
        .prepare_a1_reprint(
            surviving_b(expected_wallet, account_xpubs()[1], fingerprints()[1], a2),
            &FRESH_REPRINT_NONCE,
        )
        .expect("registered surviving-B precondition")
        .into_staged();
    let mut changed = *staged.capsule();
    changed[31] ^= 1;
    assert_eq!(
        staged.complete_scan_back(&mut changed).err(),
        Some(KitRestoreErrorV2::A1VerificationMismatch)
    );
    assert_eq!(changed, [0u8; 67], "rejected scan-back is consumed");
}

#[test]
fn every_surviving_b_fact_mismatch_rejects_before_print() {
    let wallet = wallet_id();
    let xpub = account_xpubs()[1];
    let fingerprint = fingerprints()[1];
    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));

    for case in 0..4 {
        let mut candidate_wallet = wallet;
        let mut candidate_xpub = xpub;
        let mut candidate_fingerprint = fingerprint;
        let mut candidate_a2 = a2;
        match case {
            0 => candidate_wallet[0] ^= 1,
            1 => candidate_xpub[0] ^= 1,
            2 => candidate_fingerprint[0] ^= 1,
            3 => candidate_a2[0] ^= 1,
            _ => unreachable!(),
        }
        let factor = surviving_b(
            candidate_wallet,
            candidate_xpub,
            candidate_fingerprint,
            candidate_a2,
        );
        let error = restore_error(bound().prepare_a1_reprint(factor, &FRESH_REPRINT_NONCE));
        assert_eq!(error, KitRestoreErrorV2::SurvivingBFactorMismatch);
        assert_eq!(error.name(), "SurvivingBFactorMismatch");
    }
}

#[test]
fn print_rejection_and_scan_back_difference_are_distinct() {
    let wallet = wallet_id();
    let xpub = account_xpubs()[1];
    let fingerprint = fingerprints()[1];
    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));

    let factor = surviving_b(wallet, xpub, fingerprint, a2);
    let error = restore_error(
        bound()
            .prepare_a1_reprint(factor, &FRESH_REPRINT_NONCE)
            .expect("registered surviving-B precondition")
            .complete(|_, _| A1ReprintDispositionV2::Rejected),
    );
    assert_eq!(error, KitRestoreErrorV2::A1PrintRejected);
    assert_eq!(error.name(), "A1PrintRejected");

    let factor = surviving_b(wallet, xpub, fingerprint, a2);
    let error = restore_error(
        bound()
            .prepare_a1_reprint(factor, &FRESH_REPRINT_NONCE)
            .expect("registered surviving-B precondition")
            .complete(|view, scan_back| {
                scan_back.copy_from_slice(view.capsule());
                scan_back[31] ^= 1;
                A1ReprintDispositionV2::Accepted
            }),
    );
    assert_eq!(error, KitRestoreErrorV2::A1VerificationMismatch);
    assert_eq!(error.name(), "A1VerificationMismatch");
}

#[test]
fn both_callback_unwinds_are_contained_by_the_consuming_owner_drop_paths() {
    let capsule = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let prepared = bound()
        .prepare_replacement_b(&capsule)
        .expect("registered A1 precondition");
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = prepared.complete(|_| panic!("public test unwind"));
    }))
    .is_err());

    let factor = surviving_b(
        wallet_id(),
        account_xpubs()[1],
        fingerprints()[1],
        hex_array(field(PROVISIONING, "a2_transcript_sha256")),
    );
    let prepared = bound()
        .prepare_a1_reprint(factor, &FRESH_REPRINT_NONCE)
        .expect("registered surviving-B precondition");
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = prepared.complete(|_, _| panic!("public test unwind"));
    }))
    .is_err());
}
