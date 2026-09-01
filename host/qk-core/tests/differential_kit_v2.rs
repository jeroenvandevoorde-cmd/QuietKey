//! Product-process Kit flows compared with the byte-frozen HOST simulator.

use qk_core as product;
use qk_host_sim as simulator;
use qk_io::BrokerSession;
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_psbt::ReplacementReceiveIndexV2;

const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const SPEND: &str = include_str!("../../qk-host-sim/tests/fixtures/kit_spend_v2.txt");

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("missing registered field {name}"))
}

fn hex_vec(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
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

fn share(number: u8) -> [u8; 142] {
    hex_array(field(SHARES, &format!("frame_{number}_hex")))
}

fn provisioning_descriptors() -> [[u8; 306]; 2] {
    [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ]
}

fn spend_descriptors(prefix: &str) -> [[u8; 306]; 2] {
    [
        field(SPEND, &format!("{prefix}_receive_descriptor"))
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        field(SPEND, &format!("{prefix}_change_descriptor"))
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ]
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn product_core() -> product::CoreSession {
    let grants = product::CoreDeviceGrants::validate(
        Some(product::MockDisplay::new()),
        Some(product::MockKeypad::new()),
        Some(product::MockCardSlot::new(product::CardPresence::Present)),
        false,
    )
    .expect("Kit grants");
    let (mut core, opening) =
        product::CoreSession::start(product::CoreMode::Kit, grants).expect("Kit core");
    let mut broker = BrokerSession::new();
    let reply = broker
        .accept(&decode_one(opening.frame_bytes()), None, None)
        .expect("session ready");
    core.receive(reply.frame_bytes(), false)
        .expect("session ready accepted");
    core
}

fn simulator_flow(door: simulator::KitDoorV2) -> simulator::ScreenFlowV2 {
    let mut flow = simulator::ScreenFlowV2::new(simulator::FlowKindV2::Kit);
    assert!(matches!(
        flow.apply(simulator::FlowEventV2::Key(
            simulator::KeypadKey::EqualsConfirmEnter,
        )),
        Ok(simulator::FlowApplyOutcomeV2::Continue(
            simulator::ScreenKindV2::KitDoorSelection
        ))
    ));
    assert!(matches!(
        flow.apply(simulator::FlowEventV2::SelectKitDoor(door)),
        Ok(simulator::FlowApplyOutcomeV2::Continue(
            simulator::ScreenKindV2::KitDoorConfirmation
        ))
    ));
    assert!(matches!(
        flow.apply(simulator::FlowEventV2::ConfirmKitDoor(door)),
        Ok(simulator::FlowApplyOutcomeV2::Continue(
            simulator::ScreenKindV2::ScanKitShareOne
        ))
    ));
    flow
}

fn product_ready(door: product::KitDoorV2) -> product::KitIntakeReadyV2 {
    let mut intake = product::KitIntakeSessionV2::begin(door, product::KitInputModeV2::Scanner);
    let mut first = share(1);
    assert!(matches!(
        intake.submit_scanner_frame(&mut first),
        Ok(product::KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    assert_eq!(first, [0; 142]);
    let mut second = share(2);
    let product::KitIntakeOutcomeV2::Ready(ready) = intake
        .submit_scanner_frame(&mut second)
        .expect("registered pair")
    else {
        panic!("second share must release readiness");
    };
    assert_eq!(second, [0; 142]);
    ready
}

fn simulator_ready(door: simulator::KitDoorV2) -> simulator::KitIntakeReadyV2 {
    let mut intake = simulator::KitIntakeSessionV2::begin(
        simulator_flow(door),
        simulator::KitInputModeV2::Scanner,
    )
    .expect("simulator intake");
    let mut first = share(1);
    assert!(matches!(
        intake.submit_scanner_frame(&mut first),
        Ok(simulator::KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    assert_eq!(first, [0; 142]);
    let mut second = share(2);
    let simulator::KitIntakeOutcomeV2::Ready(ready) = intake
        .submit_scanner_frame(&mut second)
        .expect("registered pair")
    else {
        panic!("second share must release readiness");
    };
    assert_eq!(second, [0; 142]);
    ready
}

#[test]
fn intake_releases_identical_public_frame_identities() {
    let product = product_ready(product::KitDoorV2::KitSpend);
    let simulator = simulator_ready(simulator::KitDoorV2::KitSpend);
    assert_eq!(product.wallet_id(), simulator.wallet_id());
    let product = product.frame_identities();
    let simulator = simulator.frame_identities();
    for (left, right) in product.into_iter().zip(simulator) {
        assert_eq!(left.share_index().as_u8(), right.share_index().as_u8());
        assert_eq!(left.wallet_id(), right.wallet_id());
        assert_eq!(left.checksum(), right.checksum());
    }
}

#[test]
fn replacement_b_returns_identical_migration_receipt_facts() {
    let descriptors = provisioning_descriptors();
    let mut core = product_core();
    let mut product = product::KitRestoreSessionV2::begin(
        &mut core,
        product_ready(product::KitDoorV2::KitRestore),
        &descriptors,
        product::HumanAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("product restore");
    product
        .select_action(product::KitRestoreActionV2::ReplacementB)
        .expect("product action");
    product
        .confirm_card_remains(product::CardRemainsStatementV2::InHand)
        .expect("product old B");
    let mut product_a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
    product
        .prepare_replacement_b(&mut product_a1)
        .expect("product surviving A1");
    let product = product
        .execute_replacement_b(product::KeypadKey::Seven, |_| {
            product::KitRestoreDispositionV2::Accepted
        })
        .expect("product replacement");

    let mut simulator = simulator::KitRestoreSessionV2::begin(
        simulator_ready(simulator::KitDoorV2::KitRestore),
        &descriptors,
        simulator::HumanAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("simulator restore");
    simulator
        .select_action(simulator::KitRestoreActionV2::ReplacementB)
        .expect("simulator action");
    simulator
        .confirm_card_remains(simulator::CardRemainsStatementV2::InHand)
        .expect("simulator old B");
    let mut simulator_a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
    simulator
        .prepare_replacement_b(&mut simulator_a1)
        .expect("simulator surviving A1");
    let simulator = simulator
        .execute_replacement_b(simulator::KeypadKey::Seven, |_| {
            simulator::KitRestoreDispositionV2::Accepted
        })
        .expect("simulator replacement");

    let product::KitRestoreArtifactV2::ReplacementB(product) = product.artifact() else {
        panic!("product replacement receipt");
    };
    let simulator::KitRestoreArtifactV2::ReplacementB(simulator) = simulator.artifact() else {
        panic!("simulator replacement receipt");
    };
    assert_eq!(product.wallet_id(), simulator.wallet_id());
    assert_eq!(product.account_xpub(), simulator.account_xpub());
    assert_eq!(product.origin_fingerprint(), simulator.origin_fingerprint());
}

#[test]
fn spend_review_identity_and_final_facts_match_the_simulator() {
    let old = spend_descriptors("old");
    let replacement = spend_descriptors("replacement");
    let destination = ReplacementReceiveIndexV2::from_untrusted(0);

    let mut core = product_core();
    let mut product = product::KitSpendSessionV2::begin(
        &mut core,
        &[1],
        product_ready(product::KitDoorV2::KitSpend),
        &old,
        product::KitSpendAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("product spend");
    let mut product_psbt = hex_vec(field(SPEND, "s0_hex"));
    product
        .submit_sweep(
            product::Source::MediaPsbt,
            &mut product_psbt,
            &replacement,
            destination,
        )
        .expect("product review");
    while product.stage() == product::KitSpendStageV2::Review {
        product.advance_review().expect("complete product review");
    }
    let product_approval = match product
        .confirm_all_funds(product::CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("product completeness")
    {
        product::KitSpendScreenV2::HumanAssertion { approval } => approval,
        _ => panic!("product assertion screen"),
    };

    let mut simulator = simulator::KitSpendSessionV2::begin(
        simulator_ready(simulator::KitDoorV2::KitSpend),
        &old,
        simulator::KitSpendAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("simulator spend");
    let mut simulator_psbt = hex_vec(field(SPEND, "s0_hex"));
    let simulator_review = simulator
        .submit_sweep(
            &mut simulator_psbt,
            qk_psbt::InputSource::MicroSd,
            &replacement,
            destination,
        )
        .expect("simulator review");
    assert_eq!(
        product_approval.review_hash(),
        simulator_review
            .review_hash()
            .expect("simulator review hash")
    );
    assert_eq!(
        simulator_review.old_wallet_id(),
        hex_array(field(SPEND, "old_wallet_id_hex"))
    );
    assert_eq!(
        simulator_review.replacement_wallet_id(),
        Some(hex_array(field(SPEND, "replacement_wallet_id_hex")))
    );
    simulator
        .confirm_completeness(simulator::CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("simulator completeness");

    let product = product
        .execute(product_approval, product::KeypadKey::Seven)
        .expect("product one sweep");
    let simulator = simulator
        .execute(simulator::KeypadKey::Seven)
        .expect("simulator one sweep");
    let product = product.facts();
    assert_eq!(product.old_wallet_id(), simulator.old_wallet_id());
    assert_eq!(
        product.replacement_wallet_id(),
        simulator.replacement_wallet_id()
    );
    assert_eq!(product.destination_index(), simulator.destination_index());
    assert_eq!(product.review_hash(), simulator.review_hash());
    assert_eq!(
        product.raw_transaction_len() as usize,
        simulator.finalized().raw_transaction().len()
    );
    assert_eq!(
        product.raw_transaction_sha256(),
        hex_array(field(SPEND, "raw_transaction_sha256"))
    );
    assert_eq!(product.txid(), simulator.finalized().txid());
    assert_eq!(product.wtxid(), simulator.finalized().wtxid());
}

#[test]
fn common_terminal_outcomes_keep_the_same_named_category() {
    let mut product = product::KitIntakeSessionV2::begin(
        product::KitDoorV2::KitSpend,
        product::KitInputModeV2::Scanner,
    );
    let product_error = product
        .interrupt(product::Interruption::SessionTimeout)
        .err()
        .expect("product timeout");
    let mut simulator = simulator::KitIntakeSessionV2::begin(
        simulator_flow(simulator::KitDoorV2::KitSpend),
        simulator::KitInputModeV2::Scanner,
    )
    .expect("simulator intake");
    let simulator_error = simulator
        .interrupt(simulator::KitIntakeInterruptionV2::SessionTimeout)
        .err()
        .expect("simulator timeout");
    assert_eq!(product_error.name(), simulator_error.name());

    let descriptors = provisioning_descriptors();
    let mut core = product_core();
    let product_error = product::KitRestoreSessionV2::begin(
        &mut core,
        product_ready(product::KitDoorV2::KitSpend),
        &descriptors,
        product::HumanAssertionDigitV2::new(0).expect("digit"),
    )
    .err()
    .expect("product wrong door");
    let simulator_error = simulator::KitRestoreSessionV2::begin(
        simulator_ready(simulator::KitDoorV2::KitSpend),
        &descriptors,
        simulator::HumanAssertionDigitV2::new(0).expect("digit"),
    )
    .err()
    .expect("simulator wrong door");
    assert_eq!(product_error.name(), simulator_error.name());
}
