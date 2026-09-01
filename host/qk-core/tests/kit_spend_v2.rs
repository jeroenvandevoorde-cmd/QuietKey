//! QK-DEC-151 Kit-Spend process-owner tests.

use qk_core::{
    CardPresence, CoordinatorCompletenessStatementV2, CoreDeviceGrants, CoreMode, CoreScreen,
    CoreSession, KeypadKey, KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2,
    KitSpendAssertionDigitV2, KitSpendErrorV2, KitSpendForeignOperationV2,
    KitSpendReviewPositionV2, KitSpendScreenV2, KitSpendSessionV2, KitSpendStageV2, MockCardSlot,
    MockDisplay, MockKeypad, NormalProfileV2, Source,
};
use qk_io::BrokerSession;
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_psbt::ReplacementReceiveIndexV2;
use std::collections::BTreeMap;

const SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const SPEND: &str = include_str!("../../qk-host-sim/tests/fixtures/kit_spend_v2.txt");

fn fields(source: &'static str) -> BTreeMap<&'static str, &'static str> {
    source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(": "))
        .collect()
}

fn hex_vec(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("registered hex")
        })
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value).try_into().expect("registered width")
}

fn descriptors(prefix: &str) -> [[u8; 306]; 2] {
    let fixture = fields(SPEND);
    [
        fixture[&*format!("{prefix}_receive_descriptor")]
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        fixture[&*format!("{prefix}_change_descriptor")]
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ]
}

fn ready(door: KitDoorV2) -> qk_core::KitIntakeReadyV2 {
    let fixture = fields(SHARES);
    let mut first = hex_array::<142>(fixture["frame_1_hex"]);
    let mut second = hex_array::<142>(fixture["frame_2_hex"]);
    let mut intake = KitIntakeSessionV2::begin(door, KitInputModeV2::Scanner);
    assert!(matches!(
        intake.submit_scanner_frame(&mut first),
        Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    assert_eq!(first, [0; 142]);
    let result = intake
        .submit_scanner_frame(&mut second)
        .expect("registered second frame");
    assert_eq!(second, [0; 142]);
    match result {
        KitIntakeOutcomeV2::Ready(ready) => ready,
        KitIntakeOutcomeV2::Continue(_) | KitIntakeOutcomeV2::FirstShareAccepted(_) => {
            panic!("second frame must complete intake")
        }
    }
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn ready_core() -> CoreSession {
    let grants = CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("Kit grants");
    let (mut core, opening) = CoreSession::start(CoreMode::Kit, grants).expect("Kit core");
    let mut broker = BrokerSession::new();
    let response = broker
        .accept(&decode_one(opening.frame_bytes()), None, None)
        .expect("session ready");
    core.receive(response.frame_bytes(), false)
        .expect("accept session ready");
    core
}

fn begin(
    profile: &[u8],
    ready: qk_core::KitIntakeReadyV2,
    old: &[[u8; 306]; 2],
    digit: KitSpendAssertionDigitV2,
) -> Result<KitSpendSessionV2, KitSpendErrorV2> {
    let mut core = ready_core();
    KitSpendSessionV2::begin(&mut core, profile, ready, old, digit)
}

fn start(profile: u8, digit: u8) -> KitSpendSessionV2 {
    begin(
        &[profile],
        ready(KitDoorV2::KitSpend),
        &descriptors("old"),
        KitSpendAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("registered Kit-Spend start")
}

fn reach_review(profile: u8, digit: u8) -> KitSpendSessionV2 {
    let fixture = fields(SPEND);
    let mut session = start(profile, digit);
    let mut psbt = hex_vec(fixture["s0_hex"]);
    assert!(matches!(
        session.submit_sweep(
            Source::MediaPsbt,
            &mut psbt,
            &descriptors("replacement"),
            ReplacementReceiveIndexV2::from_untrusted(0),
        ),
        Ok(KitSpendScreenV2::ReviewOverview { .. })
    ));
    assert!(psbt.iter().all(|byte| *byte == 0));
    session
}

fn finish_review(session: &mut KitSpendSessionV2) -> Vec<KitSpendReviewPositionV2> {
    let mut positions = Vec::new();
    while session.stage() == KitSpendStageV2::Review {
        positions.push(session.review_position().expect("review cursor"));
        session.advance_review().expect("fixed review advance");
    }
    positions
}

#[test]
fn product_bridge_binds_core_identity_and_reads_digit_without_caller_token() {
    let fixture = fields(SPEND);
    let mut core = ready_core();
    let mut session = KitSpendSessionV2::begin(
        &mut core,
        &[1],
        ready(KitDoorV2::KitSpend),
        &descriptors("old"),
        KitSpendAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("product Kit-Spend");
    assert_eq!(core.current_screen(), Some(CoreScreen::KitSpendTransaction));

    let mut psbt = hex_vec(fixture["s0_hex"]);
    session
        .submit_sweep(
            Source::MediaPsbt,
            &mut psbt,
            &descriptors("replacement"),
            ReplacementReceiveIndexV2::from_untrusted(0),
        )
        .expect("registered sweep");
    while session.stage() == KitSpendStageV2::Review {
        session
            .advance_review_in_core(&mut core)
            .expect("visit bound review fact");
    }
    session
        .confirm_all_funds_in_core(
            &mut core,
            CoordinatorCompletenessStatementV2::AllFundsIncluded,
        )
        .expect("completeness statement");
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitSpendHumanAssertion)
    );
    let outcome = session
        .execute_in_core(&mut core, KeypadKey::Seven)
        .expect("digit read then immediate sweep signing");
    assert_eq!(
        outcome.facts().raw_transaction_sha256(),
        hex_array(fixture["raw_transaction_sha256"])
    );
}

fn key_for_digit(digit: u8) -> KeypadKey {
    match digit {
        0 => KeypadKey::Zero,
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        9 => KeypadKey::Nine,
        _ => panic!("test digit"),
    }
}

#[test]
fn every_profile_visits_the_complete_review_and_finalizes_raw_only() {
    let fixture = fields(SPEND);
    let expected_positions = vec![
        KitSpendReviewPositionV2::Overview,
        KitSpendReviewPositionV2::Arithmetic,
        KitSpendReviewPositionV2::Recipient(0),
        KitSpendReviewPositionV2::Locktime,
        KitSpendReviewPositionV2::Sequence(0),
        KitSpendReviewPositionV2::FeePolicy,
        KitSpendReviewPositionV2::FeeFacts,
        KitSpendReviewPositionV2::Warning(0),
        KitSpendReviewPositionV2::Warning(1),
    ];

    for (profile_byte, profile) in [
        (1, NormalProfileV2::SimpleRecovery),
        (2, NormalProfileV2::Inheritance),
        (3, NormalProfileV2::QuantumShelter),
    ] {
        let mut session = reach_review(profile_byte, 7);
        assert_eq!(finish_review(&mut session), expected_positions);
        assert_eq!(session.stage(), KitSpendStageV2::CompletenessStatement);
        let assertion = session
            .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
            .expect("external completeness statement");
        let approval = match assertion {
            KitSpendScreenV2::HumanAssertion { approval } => approval,
            _ => panic!("assertion screen"),
        };
        assert_eq!(approval.assertion_digit().value(), 7);
        assert_eq!(approval.token().cycle(), 1);
        assert_eq!(
            approval.review_hash(),
            hex_array(fixture["review_hash_hex"])
        );

        let outcome = session
            .execute(approval, key_for_digit(7))
            .expect("one consuming sweep");
        let facts = outcome.facts();
        assert_eq!(facts.profile(), profile);
        assert_eq!(
            facts.old_wallet_id(),
            hex_array(fixture["old_wallet_id_hex"])
        );
        assert_eq!(
            facts.replacement_wallet_id(),
            hex_array(fixture["replacement_wallet_id_hex"])
        );
        assert_eq!(facts.destination_index(), 0);
        assert_eq!(facts.raw_transaction_len(), 315);
        assert_eq!(
            facts.raw_transaction_sha256(),
            hex_array(fixture["raw_transaction_sha256"])
        );
        assert_eq!(facts.txid(), hex_array(fixture["txid_raw_hex"]));
        assert_eq!(facts.wtxid(), hex_array(fixture["wtxid_raw_hex"]));
        assert_eq!(
            outcome.completeness(),
            CoordinatorCompletenessStatementV2::AllFundsIncluded
        );
    }
}

#[test]
fn profile_old_descriptor_and_source_rejections_are_distinct_and_wipe() {
    for (bytes, expected) in [
        (&[][..], KitSpendErrorV2::ProfileMissing),
        (&[0][..], KitSpendErrorV2::ProfileUnknown),
        (&[1, 2][..], KitSpendErrorV2::ProfileMalformed),
    ] {
        assert_eq!(
            begin(
                bytes,
                ready(KitDoorV2::KitSpend),
                &descriptors("old"),
                KitSpendAssertionDigitV2::new(0).expect("digit"),
            )
            .err(),
            Some(expected)
        );
    }

    assert_eq!(
        begin(
            &[1],
            ready(KitDoorV2::KitRestore),
            &descriptors("old"),
            KitSpendAssertionDigitV2::new(0).expect("digit"),
        )
        .err(),
        Some(KitSpendErrorV2::WrongDoor)
    );

    let mut old = descriptors("old");
    old[0][0] ^= 1;
    assert_eq!(
        begin(
            &[1],
            ready(KitDoorV2::KitSpend),
            &old,
            KitSpendAssertionDigitV2::new(0).expect("digit"),
        )
        .err(),
        Some(KitSpendErrorV2::RecoveredWalletMismatch)
    );

    let fixture = fields(SPEND);
    let mut session = start(1, 0);
    let mut psbt = hex_vec(fixture["s0_hex"]);
    assert_eq!(
        session
            .submit_sweep(
                Source::CameraKitCandidate,
                &mut psbt,
                &descriptors("replacement"),
                ReplacementReceiveIndexV2::from_untrusted(0),
            )
            .err(),
        Some(KitSpendErrorV2::WrongIngressSource)
    );
    assert!(psbt.iter().all(|byte| *byte == 0));
    assert_eq!(session.failure(), Some(KitSpendErrorV2::WrongIngressSource));
}

#[test]
fn completed_review_has_no_yield_and_wrong_digit_has_no_retry() {
    let fixture = fields(SPEND);
    let mut before_statement = reach_review(1, 4);
    finish_review(&mut before_statement);
    assert_eq!(
        before_statement.advance_review().err(),
        Some(KitSpendErrorV2::PostApprovalYield)
    );

    let mut session = reach_review(1, 4);
    finish_review(&mut session);
    session
        .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("completeness");
    assert_eq!(
        session.reject_foreign_operation(KitSpendForeignOperationV2::Transport),
        Err(KitSpendErrorV2::PostApprovalYield)
    );
    assert_eq!(session.failure(), Some(KitSpendErrorV2::PostApprovalYield));

    let mut transport = reach_review(1, 4);
    finish_review(&mut transport);
    let mut psbt = hex_vec(fixture["s0_hex"]);
    assert_eq!(
        transport
            .submit_sweep(
                Source::MediaPsbt,
                &mut psbt,
                &descriptors("replacement"),
                ReplacementReceiveIndexV2::from_untrusted(0),
            )
            .err(),
        Some(KitSpendErrorV2::PostApprovalYield)
    );
    assert!(psbt.iter().all(|byte| *byte == 0));

    let mut second = reach_review(1, 4);
    finish_review(&mut second);
    let approval = match second
        .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("completeness")
    {
        KitSpendScreenV2::HumanAssertion { approval } => approval,
        _ => panic!("assertion screen"),
    };
    assert_eq!(
        second.execute(approval, KeypadKey::Five).err(),
        Some(KitSpendErrorV2::HumanAssertionMismatch)
    );
}

#[test]
fn all_ten_ratified_digits_gate_the_same_consuming_sweep() {
    let fixture = fields(SPEND);
    for digit in 0..=9 {
        let mut session = reach_review(1, digit);
        finish_review(&mut session);
        let approval = match session
            .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
            .expect("completeness")
        {
            KitSpendScreenV2::HumanAssertion { approval } => approval,
            _ => panic!("assertion screen"),
        };
        assert_eq!(approval.assertion_digit().value(), digit);
        let outcome = session
            .execute(approval, key_for_digit(digit))
            .expect("matching digit signs exactly once");
        assert_eq!(outcome.facts().txid(), hex_array(fixture["txid_raw_hex"]));
    }
}

#[test]
fn equal_replacement_wallet_and_over_cap_index_keep_named_precedence() {
    let fixture = fields(SPEND);
    let mut session = start(1, 0);
    let mut psbt = hex_vec(fixture["s0_hex"]);
    assert_eq!(
        session
            .submit_sweep(
                Source::MediaPsbt,
                &mut psbt,
                &descriptors("old"),
                ReplacementReceiveIndexV2::from_untrusted(0),
            )
            .err(),
        Some(KitSpendErrorV2::ReplacementWalletUnchanged)
    );
    assert!(psbt.iter().all(|byte| *byte == 0));

    let mut session = start(1, 0);
    let mut psbt = hex_vec(fixture["s0_hex"]);
    let error = session
        .submit_sweep(
            Source::MediaPsbt,
            &mut psbt,
            &descriptors("replacement"),
            ReplacementReceiveIndexV2::from_untrusted(65_536),
        )
        .err()
        .expect("over-cap rejection");
    assert_eq!(error.name(), "DestinationIndexOutOfRange");
    assert!(psbt.iter().all(|byte| *byte == 0));
}
