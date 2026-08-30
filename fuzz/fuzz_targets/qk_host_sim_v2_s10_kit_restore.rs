#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    A1ReprintDispositionV2, CardRemainsStatementV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, HumanAssertionDigitV2, KeypadKey, KitDoorV2, KitInputModeV2,
    KitIntakeOutcomeV2, KitIntakeSessionV2, KitRestoreActionV2, KitRestoreArtifactV2,
    KitRestoreDispositionV2, KitRestoreErrorV2, KitRestoreForeignOperationV2,
    KitRestoreInterruptionV2, KitRestoreSessionV2, KitRestoreStageV2,
    MandatoryFreshWalletMigrationV2, ScreenFlowV2, ScreenKindV2, SurvivingBFactorV2,
    WipingReasonV2, KIT_FALLBACK_TABLE_V2,
};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

#[allow(dead_code)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_BYTES: usize = 512;
const SCENARIOS: u8 = 23;
const CAPSULE_BYTES: usize = 67;
const FRAME_BYTES: usize = 142;
const FALLBACK_SYMBOLS: usize = 228;

const PROVISIONING: &str =
    include_str!("../../host/qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &str = include_str!("../../host/qk-kit/tests/fixtures/kit_share_v2.txt");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactKind {
    ReplacementB,
    A1Reprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Summary {
    Success {
        artifact: ArtifactKind,
        mode: KitInputModeV2,
        indices: [u8; 2],
        wallet_id: [u8; 32],
        nonce: Option<[u8; 12]>,
        capsule_sha256: Option<[u8; 32]>,
        sink_calls: u8,
    },
    Rejected {
        error: &'static str,
        terminal: Option<FlowTerminalV2>,
        sink_calls: u8,
    },
    Dropped {
        stage: KitRestoreStageV2,
        action: Option<KitRestoreActionV2>,
    },
}

#[derive(Clone, Copy)]
struct PublicContext {
    mode: KitInputModeV2,
    indices: [u8; 2],
    wallet_id: [u8; 32],
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each byte is uniquely borrowed and live for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered fixture field")
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("registered lowercase hex"),
    }
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
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

fn wallet_id() -> [u8; 32] {
    hex_array(field(PROVISIONING, "wallet_id"))
}

fn reference_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = reference_sha256::Sha256::new();
    hasher.update(bytes).expect("bounded public artifact");
    hasher.finalize().expect("bounded public artifact digest")
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("active Kit topology"),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn flow_at_share_one(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    root_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
    root_continue(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(door),
        ScreenKindV2::ScanKitShareOne,
    );
    flow
}

fn digit_key(digit: u8) -> KeypadKey {
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
        _ => panic!("bounded decimal digit"),
    }
}

fn coordinate_key(number: usize) -> KeypadKey {
    match number {
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        _ => panic!("bounded fallback coordinate"),
    }
}

fn append_fallback_symbol(session: &mut KitIntakeSessionV2, symbol: u8) {
    let position = KIT_FALLBACK_TABLE_V2
        .iter()
        .flatten()
        .position(|candidate| *candidate == symbol)
        .expect("registered fallback alphabet");
    assert!(matches!(
        session
            .apply_fallback_key(coordinate_key(position / 8 + 1))
            .expect("valid fallback row"),
        KitIntakeOutcomeV2::Continue(_)
    ));
    assert!(matches!(
        session
            .apply_fallback_key(coordinate_key(position % 8 + 1))
            .expect("valid fallback column"),
        KitIntakeOutcomeV2::Continue(_)
    ));
}

fn enter_fallback(session: &mut KitIntakeSessionV2, symbols: &[u8; FALLBACK_SYMBOLS]) {
    for symbol in symbols {
        append_fallback_symbol(session, *symbol);
    }
}

fn intake_ready(door: KitDoorV2, variant: u8) -> qk_host_sim::KitIntakeReadyV2 {
    let reversed = variant & 1 != 0;
    let fallback = variant & 2 != 0;
    if fallback {
        let fallback_one: &[u8; FALLBACK_SYMBOLS] = field(KIT_SHARES, "fallback_1_ascii")
            .as_bytes()
            .try_into()
            .expect("registered fallback one width");
        let fallback_two: &[u8; FALLBACK_SYMBOLS] = field(KIT_SHARES, "fallback_2_ascii")
            .as_bytes()
            .try_into()
            .expect("registered fallback two width");
        let (first, second) = if reversed {
            (fallback_two, fallback_one)
        } else {
            (fallback_one, fallback_two)
        };
        let mut session =
            KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                .expect("valid fallback intake start");
        enter_fallback(&mut session, first);
        assert!(matches!(
            session
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .expect("registered first fallback"),
            KitIntakeOutcomeV2::FirstShareAccepted(_)
        ));
        enter_fallback(&mut session, second);
        let KitIntakeOutcomeV2::Ready(ready) = session
            .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
            .expect("registered second fallback")
        else {
            panic!("registered fallback pair must release readiness");
        };
        ready
    } else {
        let mut frame_one = hex_array::<FRAME_BYTES>(field(KIT_SHARES, "frame_1_hex"));
        let mut frame_two = hex_array::<FRAME_BYTES>(field(KIT_SHARES, "frame_2_hex"));
        let (first, second) = if reversed {
            (&mut frame_two, &mut frame_one)
        } else {
            (&mut frame_one, &mut frame_two)
        };
        let mut session =
            KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                .expect("valid scanner intake start");
        assert!(matches!(
            session
                .submit_scanner_frame(first)
                .expect("registered first frame"),
            KitIntakeOutcomeV2::FirstShareAccepted(_)
        ));
        assert_eq!(*first, [0u8; FRAME_BYTES]);
        let KitIntakeOutcomeV2::Ready(ready) = session
            .submit_scanner_frame(second)
            .expect("registered second frame")
        else {
            panic!("registered frame pair must release readiness");
        };
        assert_eq!(*second, [0u8; FRAME_BYTES]);
        ready
    }
}

fn expected_context(variant: u8) -> PublicContext {
    PublicContext {
        mode: if variant & 2 == 0 {
            KitInputModeV2::Scanner
        } else {
            KitInputModeV2::Fallback
        },
        indices: if variant & 1 == 0 { [1, 2] } else { [2, 1] },
        wallet_id: wallet_id(),
    }
}

fn begin_session(variant: u8, digit: u8) -> (KitRestoreSessionV2, PublicContext) {
    let context = expected_context(variant);
    let session = KitRestoreSessionV2::begin(
        intake_ready(KitDoorV2::KitRestore, variant),
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("bounded digit"),
    )
    .expect("registered Kit-Restore ready owner must bind");
    let screen = session.screen().expect("active action-selection screen");
    assert_eq!(screen.stage(), KitRestoreStageV2::ActionSelection);
    assert_eq!(screen.wallet_id(), context.wallet_id);
    assert_eq!(screen.input_mode(), context.mode);
    assert_eq!(screen.action(), None);
    assert_eq!(screen.assertion_digit(), None);
    assert_eq!(
        session
            .frame_identities()
            .map(|identity| identity.share_index().as_u8()),
        context.indices
    );
    assert_eq!(
        session
            .frame_identities()
            .map(|identity| identity.wallet_id()),
        [context.wallet_id; 2]
    );
    (session, context)
}

fn nonce(data: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    for (index, byte) in nonce.iter_mut().enumerate() {
        *byte = data
            .get(4 + index)
            .copied()
            .unwrap_or(b'S'.wrapping_add(index as u8));
    }
    let old = hex_array::<12>(field(PROVISIONING, "a1_nonce_hex"));
    if nonce == old {
        nonce[11] ^= 1;
    }
    nonce
}

fn surviving_b(mutation: Option<u8>) -> SurvivingBFactorV2 {
    let mut wallet = wallet_id();
    let mut account_xpub: [u8; 111] = field(PROVISIONING, "role_b_account_xpub")
        .as_bytes()
        .try_into()
        .expect("registered B xpub width");
    let mut fingerprint = hex_array::<4>(field(PROVISIONING, "role_b_origin_fingerprint"));
    let mut a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    if let Some(selector) = mutation {
        match selector % 4 {
            0 => wallet[usize::from(selector) % wallet.len()] ^= 1,
            1 => account_xpub[usize::from(selector) % account_xpub.len()] ^= 1,
            2 => fingerprint[usize::from(selector) % fingerprint.len()] ^= 1,
            _ => a2[usize::from(selector) % a2.len()] ^= 1,
        }
    }
    let factor = SurvivingBFactorV2::take(wallet, account_xpub, fingerprint, &mut a2);
    assert_eq!(a2, [0u8; 32]);
    factor
}

fn select_replacement_to_preparation(session: &mut KitRestoreSessionV2) {
    let selected = session
        .select_action(KitRestoreActionV2::ReplacementB)
        .expect("replacement action selection");
    assert_eq!(selected.stage(), KitRestoreStageV2::CardRemainsConfirmation);
    assert_eq!(selected.action(), Some(KitRestoreActionV2::ReplacementB));
    assert_eq!(selected.assertion_digit(), None);
    let confirmed = session
        .confirm_card_remains(CardRemainsStatementV2::InHand)
        .expect("old B remains in hand");
    assert_eq!(confirmed.stage(), KitRestoreStageV2::BranchPreparation);
}

fn prepare_replacement(session: &mut KitRestoreSessionV2, digit: u8) {
    select_replacement_to_preparation(session);
    let mut surviving_a1 = hex_array::<CAPSULE_BYTES>(field(PROVISIONING, "a1_capsule_hex"));
    let prepared = session
        .prepare_replacement_b(&mut surviving_a1)
        .expect("registered surviving A1");
    assert_eq!(surviving_a1, [0u8; CAPSULE_BYTES]);
    assert_eq!(prepared.stage(), KitRestoreStageV2::HumanAssertion);
    assert_eq!(prepared.action(), Some(KitRestoreActionV2::ReplacementB));
    assert_eq!(
        prepared.assertion_digit().map(HumanAssertionDigitV2::value),
        Some(digit)
    );
}

fn prepare_a1(session: &mut KitRestoreSessionV2, nonce: &[u8; 12], digit: u8) {
    let selected = session
        .select_action(KitRestoreActionV2::A1Reprint)
        .expect("A1 action selection");
    assert_eq!(selected.stage(), KitRestoreStageV2::BranchPreparation);
    assert_eq!(selected.action(), Some(KitRestoreActionV2::A1Reprint));
    let prepared = session
        .prepare_a1_reprint(surviving_b(None), nonce)
        .expect("registered surviving B facts");
    assert_eq!(prepared.stage(), KitRestoreStageV2::HumanAssertion);
    assert_eq!(prepared.action(), Some(KitRestoreActionV2::A1Reprint));
    assert_eq!(
        prepared.assertion_digit().map(HumanAssertionDigitV2::value),
        Some(digit)
    );
}

fn post_terminal(session: &mut KitRestoreSessionV2) {
    let terminal = session.terminal();
    let failure = session.failure();
    assert_eq!(
        session.select_action(KitRestoreActionV2::ReplacementB),
        Err(KitRestoreErrorV2::Finished)
    );
    assert_eq!(
        session.confirm_card_remains(CardRemainsStatementV2::InHand),
        Err(KitRestoreErrorV2::Finished)
    );
    let mut scratch = [0xa5; CAPSULE_BYTES];
    assert_eq!(
        session.prepare_replacement_b(&mut scratch),
        Err(KitRestoreErrorV2::Finished)
    );
    assert_eq!(scratch, [0u8; CAPSULE_BYTES]);
    assert_eq!(
        session.reject_foreign_operation(KitRestoreForeignOperationV2::Signing),
        Err(KitRestoreErrorV2::Finished)
    );
    assert_eq!(
        session.interrupt(KitRestoreInterruptionV2::Cancelled),
        Err(KitRestoreErrorV2::Finished)
    );
    assert_eq!(session.terminal(), terminal);
    assert_eq!(session.failure(), failure);
}

fn rejected<T>(
    result: Result<T, KitRestoreErrorV2>,
    session: &mut KitRestoreSessionV2,
    expected: KitRestoreErrorV2,
    reason: WipingReasonV2,
    sink_calls: u8,
) -> Summary {
    let error = result.err().expect("scenario must reject");
    assert_eq!(error, expected);
    assert_eq!(error.name(), expected.name());
    assert_eq!(error.to_string(), expected.name());
    assert_eq!(session.screen(), None);
    assert_eq!(session.failure(), Some(expected));
    assert_eq!(
        session.terminal(),
        Some(FlowTerminalV2::FailedWiped(reason))
    );
    post_terminal(session);
    Summary::Rejected {
        error: error.name(),
        terminal: session.terminal(),
        sink_calls,
    }
}

fn consumed_rejection(
    error: KitRestoreErrorV2,
    expected: KitRestoreErrorV2,
    sink_calls: u8,
) -> Summary {
    assert_eq!(error, expected);
    assert_eq!(error.name(), expected.name());
    assert_eq!(error.to_string(), expected.name());
    Summary::Rejected {
        error: error.name(),
        terminal: None,
        sink_calls,
    }
}

fn constructor_rejection(error: KitRestoreErrorV2, expected: KitRestoreErrorV2) -> Summary {
    consumed_rejection(error, expected, 0)
}

fn fast_rejection(data: &[u8]) -> Summary {
    let invalid = 10 + (data.get(3).copied().unwrap_or(0) % 246);
    let error = HumanAssertionDigitV2::new(invalid)
        .err()
        .expect("out-of-range assertion digit must reject");
    constructor_rejection(error, KitRestoreErrorV2::InvalidHumanAssertionDigit)
}

fn selector(data: &[u8]) -> u8 {
    data.iter()
        .fold(0x6du8, |state, byte| state.wrapping_mul(33) ^ byte)
}

fn selected_scenario(data: &[u8]) -> Option<u8> {
    if selector(data) != 0 {
        return None;
    }
    let scenario = data.first().copied()?.checked_sub(b'.')?;
    (scenario < SCENARIOS).then_some(scenario)
}

fn run(data: &[u8], scenario: u8) -> Summary {
    let variant = data.get(1).copied().unwrap_or(0) % 4;
    let digit = data.get(2).copied().unwrap_or(0) % 10;
    let nonce = nonce(data);

    match scenario {
        0 => {
            let (mut session, context) = begin_session(variant, digit);
            prepare_replacement(&mut session, digit);
            let expected_xpub: [u8; 111] = field(PROVISIONING, "role_b_account_xpub")
                .as_bytes()
                .try_into()
                .unwrap();
            let expected_fingerprint =
                hex_array::<4>(field(PROVISIONING, "role_b_origin_fingerprint"));
            let mut calls = 0u8;
            let outcome = session
                .execute_replacement_b(digit_key(digit), |view| {
                    calls += 1;
                    assert_eq!(*view.wallet_id(), context.wallet_id);
                    assert_eq!(*view.account_xpub(), expected_xpub);
                    assert_eq!(*view.origin_fingerprint(), expected_fingerprint);
                    KitRestoreDispositionV2::Accepted
                })
                .expect("accepted replacement boundary");
            assert_eq!(calls, 1);
            assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
            let KitRestoreArtifactV2::ReplacementB(receipt) = outcome.artifact() else {
                panic!("replacement action returned wrong artifact");
            };
            assert_eq!(receipt.wallet_id(), context.wallet_id);
            assert_eq!(receipt.account_xpub(), expected_xpub);
            assert_eq!(receipt.origin_fingerprint(), expected_fingerprint);
            Summary::Success {
                artifact: ArtifactKind::ReplacementB,
                mode: context.mode,
                indices: context.indices,
                wallet_id: context.wallet_id,
                nonce: None,
                capsule_sha256: None,
                sink_calls: calls,
            }
        }
        1 => {
            let (mut session, context) = begin_session(variant, digit);
            prepare_a1(&mut session, &nonce, digit);
            let mut seed_a = hex_array::<32>(field(PROVISIONING, "seed_a_transcript_sha256"));
            let mut a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
            let mut old_capsule = hex_array::<CAPSULE_BYTES>(field(PROVISIONING, "a1_capsule_hex"));
            let mut capsule_sha256 = [0u8; 32];
            let mut calls = 0u8;
            let outcome = session
                .execute_a1_reprint(digit_key(digit), |view, scan_back| {
                    calls += 1;
                    assert_eq!(&view.capsule()[..7], b"QKA1\x01\x01\x01");
                    assert_eq!(&view.capsule()[7..19], &nonce);
                    assert_ne!(view.capsule(), &old_capsule);
                    let mut recovered = [0xa5; 32];
                    assert_eq!(
                        qk_a1::decrypt(&a2, &context.wallet_id, view.capsule(), &mut recovered),
                        Ok(())
                    );
                    assert_eq!(recovered, seed_a);
                    wipe(&mut recovered);
                    capsule_sha256 = reference_hash(view.capsule());
                    scan_back.copy_from_slice(view.capsule());
                    A1ReprintDispositionV2::Accepted
                })
                .expect("accepted A1 print and scan-back boundary");
            assert_eq!(calls, 1);
            assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
            let KitRestoreArtifactV2::A1Reprint(receipt) = outcome.artifact() else {
                panic!("A1 action returned wrong artifact");
            };
            assert_eq!(receipt.wallet_id(), context.wallet_id);
            assert_eq!(receipt.nonce(), nonce);
            assert_eq!(receipt.capsule_sha256(), capsule_sha256);
            wipe(&mut seed_a);
            wipe(&mut a2);
            wipe(&mut old_capsule);
            Summary::Success {
                artifact: ArtifactKind::A1Reprint,
                mode: context.mode,
                indices: context.indices,
                wallet_id: context.wallet_id,
                nonce: Some(nonce),
                capsule_sha256: Some(capsule_sha256),
                sink_calls: calls,
            }
        }
        2 => {
            let ready = intake_ready(KitDoorV2::KitSpend, variant);
            let error = match KitRestoreSessionV2::begin(
                ready,
                &descriptors(),
                HumanAssertionDigitV2::new(digit).unwrap(),
            ) {
                Err(error) => error,
                Ok(_) => panic!("Kit-Spend readiness entered Kit-Restore"),
            };
            constructor_rejection(error, KitRestoreErrorV2::WrongDoor)
        }
        3 => {
            let mut wrong = descriptors();
            let offset = usize::from(data.get(3).copied().unwrap_or(0)) % wrong[0].len();
            wrong[0][offset] ^= 1;
            let error = match KitRestoreSessionV2::begin(
                intake_ready(KitDoorV2::KitRestore, variant),
                &wrong,
                HumanAssertionDigitV2::new(digit).unwrap(),
            ) {
                Err(error) => error,
                Ok(_) => panic!("mismatched D entered Kit-Restore"),
            };
            constructor_rejection(error, KitRestoreErrorV2::RecoveredWalletMismatch)
        }
        4 => {
            let (mut session, _) = begin_session(variant, digit);
            let first = if data.get(3).copied().unwrap_or(0) & 1 == 0 {
                KitRestoreActionV2::ReplacementB
            } else {
                KitRestoreActionV2::A1Reprint
            };
            session.select_action(first).unwrap();
            let second = match first {
                KitRestoreActionV2::ReplacementB => KitRestoreActionV2::A1Reprint,
                KitRestoreActionV2::A1Reprint => KitRestoreActionV2::ReplacementB,
            };
            let result = session.select_action(second);
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::ActionSwitchAttempt,
                WipingReasonV2::DoorSwitchAttempt,
                0,
            )
        }
        5 => {
            let (mut session, _) = begin_session(variant, digit);
            if data.get(3).copied().unwrap_or(0) & 1 != 0 {
                session
                    .select_action(KitRestoreActionV2::A1Reprint)
                    .unwrap();
            }
            let result = session.confirm_card_remains(CardRemainsStatementV2::InHand);
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::RestoreModeMismatch,
                WipingReasonV2::InvalidTransition,
                0,
            )
        }
        6 => {
            let (mut session, _) = begin_session(variant, digit);
            session
                .select_action(KitRestoreActionV2::ReplacementB)
                .unwrap();
            let result = session.confirm_card_remains(CardRemainsStatementV2::Missing);
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::MissingCardRequiresKitSpend,
                WipingReasonV2::MissingCardRequiresKitSpend,
                0,
            )
        }
        7 => {
            let (mut session, _) = begin_session(variant, digit);
            select_replacement_to_preparation(&mut session);
            let mut capsule = hex_array::<CAPSULE_BYTES>(field(PROVISIONING, "a1_capsule_hex"));
            let offset = usize::from(data.get(3).copied().unwrap_or(0)) % capsule.len();
            capsule[offset] ^= 1;
            let result = session.prepare_replacement_b(&mut capsule);
            assert_eq!(capsule, [0u8; CAPSULE_BYTES]);
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::SurvivingA1Mismatch,
                WipingReasonV2::OperationFailed,
                0,
            )
        }
        8 => {
            let (mut session, _) = begin_session(variant, digit);
            session
                .select_action(KitRestoreActionV2::A1Reprint)
                .unwrap();
            let result = session
                .prepare_a1_reprint(surviving_b(Some(data.get(3).copied().unwrap_or(0))), &nonce);
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::SurvivingBFactorMismatch,
                WipingReasonV2::OperationFailed,
                0,
            )
        }
        9 | 10 => {
            let (mut session, _) = begin_session(variant, digit);
            prepare_replacement(&mut session, digit);
            let mut calls = 0u8;
            let key = if scenario == 9 {
                digit_key((digit + 1) % 10)
            } else {
                KeypadKey::CancelBack
            };
            let error = session
                .execute_replacement_b(key, |_| {
                    calls += 1;
                    KitRestoreDispositionV2::Accepted
                })
                .err()
                .expect("wrong assertion key must reject");
            let expected = if scenario == 9 {
                KitRestoreErrorV2::HumanAssertionMismatch
            } else {
                KitRestoreErrorV2::Cancelled
            };
            assert_eq!(calls, 0);
            consumed_rejection(error, expected, calls)
        }
        11 => {
            let (mut session, context) = begin_session(variant, digit);
            prepare_replacement(&mut session, digit);
            let mut calls = 0u8;
            let error = session
                .execute_replacement_b(digit_key(digit), |view| {
                    calls += 1;
                    assert_eq!(*view.wallet_id(), context.wallet_id);
                    KitRestoreDispositionV2::Rejected
                })
                .err()
                .expect("rejected replacement sink");
            assert_eq!(calls, 1);
            consumed_rejection(error, KitRestoreErrorV2::ReplacementBRejected, calls)
        }
        12 | 13 => {
            let (mut session, _) = begin_session(variant, digit);
            prepare_a1(&mut session, &nonce, digit);
            let mut calls = 0u8;
            let key = if scenario == 12 {
                digit_key((digit + 1) % 10)
            } else {
                KeypadKey::CancelBack
            };
            let error = session
                .execute_a1_reprint(key, |view, scan_back| {
                    calls += 1;
                    scan_back.copy_from_slice(view.capsule());
                    A1ReprintDispositionV2::Accepted
                })
                .err()
                .expect("wrong assertion key must reject");
            let expected = if scenario == 12 {
                KitRestoreErrorV2::HumanAssertionMismatch
            } else {
                KitRestoreErrorV2::Cancelled
            };
            assert_eq!(calls, 0);
            consumed_rejection(error, expected, calls)
        }
        14 | 15 => {
            let (mut session, _) = begin_session(variant, digit);
            prepare_a1(&mut session, &nonce, digit);
            let mut calls = 0u8;
            let error = session
                .execute_a1_reprint(digit_key(digit), |view, scan_back| {
                    calls += 1;
                    assert_eq!(&view.capsule()[7..19], &nonce);
                    if scenario == 14 {
                        A1ReprintDispositionV2::Rejected
                    } else {
                        scan_back.copy_from_slice(view.capsule());
                        let offset =
                            usize::from(data.get(3).copied().unwrap_or(0)) % scan_back.len();
                        scan_back[offset] ^= 1;
                        A1ReprintDispositionV2::Accepted
                    }
                })
                .err()
                .expect("hostile A1 sink must reject");
            assert_eq!(calls, 1);
            let expected = if scenario == 14 {
                KitRestoreErrorV2::A1PrintRejected
            } else {
                KitRestoreErrorV2::A1VerificationMismatch
            };
            consumed_rejection(error, expected, calls)
        }
        16 => {
            let (mut session, _) = begin_session(variant, digit);
            let stage = data.get(3).copied().unwrap_or(0) % 6;
            match stage {
                0 => {}
                1 => {
                    session
                        .select_action(KitRestoreActionV2::ReplacementB)
                        .unwrap();
                }
                2 => {
                    select_replacement_to_preparation(&mut session);
                }
                3 => {
                    session
                        .select_action(KitRestoreActionV2::A1Reprint)
                        .unwrap();
                }
                4 => {
                    prepare_replacement(&mut session, digit);
                }
                _ => {
                    prepare_a1(&mut session, &nonce, digit);
                }
            }
            let screen = session.screen().expect("active interruption stage");
            let expected_stage = match stage {
                0 => KitRestoreStageV2::ActionSelection,
                1 => KitRestoreStageV2::CardRemainsConfirmation,
                2 | 3 => KitRestoreStageV2::BranchPreparation,
                _ => KitRestoreStageV2::HumanAssertion,
            };
            let expected_action = match stage {
                0 => None,
                1 | 2 | 4 => Some(KitRestoreActionV2::ReplacementB),
                _ => Some(KitRestoreActionV2::A1Reprint),
            };
            assert_eq!(screen.stage(), expected_stage);
            assert_eq!(screen.action(), expected_action);
            let selected = data.get(2).copied().unwrap_or(0) % 8;
            let (interruption, expected, reason) = match selected {
                0 => (
                    KitRestoreInterruptionV2::Cancelled,
                    KitRestoreErrorV2::Cancelled,
                    WipingReasonV2::Cancelled,
                ),
                1 => (
                    KitRestoreInterruptionV2::OperationFailed,
                    KitRestoreErrorV2::OperationFailed,
                    WipingReasonV2::OperationFailed,
                ),
                2 => (
                    KitRestoreInterruptionV2::MediaRemoved,
                    KitRestoreErrorV2::MediaRemoved,
                    WipingReasonV2::MediaRemoved,
                ),
                3 => (
                    KitRestoreInterruptionV2::CardRemoved,
                    KitRestoreErrorV2::CardRemoved,
                    WipingReasonV2::CardRemoved,
                ),
                4 => (
                    KitRestoreInterruptionV2::SessionTimeout,
                    KitRestoreErrorV2::SessionTimeout,
                    WipingReasonV2::SessionTimeout,
                ),
                5 => (
                    KitRestoreInterruptionV2::Shutdown,
                    KitRestoreErrorV2::Shutdown,
                    WipingReasonV2::Shutdown,
                ),
                6 => (
                    KitRestoreInterruptionV2::Restart,
                    KitRestoreErrorV2::Restart,
                    WipingReasonV2::Restart,
                ),
                _ => (
                    KitRestoreInterruptionV2::PowerLoss,
                    KitRestoreErrorV2::PowerLoss,
                    WipingReasonV2::PowerLoss,
                ),
            };
            let result = session.interrupt(interruption);
            rejected(result, &mut session, expected, reason, 0)
        }
        17 => {
            let (mut session, _) = begin_session(variant, digit);
            let selected = data.get(2).copied().unwrap_or(0) % 10;
            let (operation, expected, reason) = match selected {
                0 => (
                    KitRestoreForeignOperationV2::Signing,
                    KitRestoreErrorV2::SigningProhibited,
                    WipingReasonV2::RestoreSigningProhibited,
                ),
                1 => (
                    KitRestoreForeignOperationV2::Transaction,
                    KitRestoreErrorV2::TransactionProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                2 => (
                    KitRestoreForeignOperationV2::Review,
                    KitRestoreErrorV2::ReviewProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                3 => (
                    KitRestoreForeignOperationV2::Approval,
                    KitRestoreErrorV2::ApprovalProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                4 => (
                    KitRestoreForeignOperationV2::Export,
                    KitRestoreErrorV2::ExportProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                5 => (
                    KitRestoreForeignOperationV2::Intake,
                    KitRestoreErrorV2::ForeignInputProhibited,
                    WipingReasonV2::KitScannerModeMismatch,
                ),
                6 => (
                    KitRestoreForeignOperationV2::GenericWalletOutput,
                    KitRestoreErrorV2::GenericWalletOutputProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                7 => (
                    KitRestoreForeignOperationV2::KitGeneration,
                    KitRestoreErrorV2::KitGenerationProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                8 => (
                    KitRestoreForeignOperationV2::KitRegeneration,
                    KitRestoreErrorV2::KitRegenerationProhibited,
                    WipingReasonV2::OperationFailed,
                ),
                _ => (
                    KitRestoreForeignOperationV2::DoorSwitch,
                    KitRestoreErrorV2::DoorSwitchAttempt,
                    WipingReasonV2::DoorSwitchAttempt,
                ),
            };
            let result = session.reject_foreign_operation(operation);
            rejected(result, &mut session, expected, reason, 0)
        }
        18 => fast_rejection(data),
        19 => {
            let (mut session, _) = begin_session(variant, digit);
            let result = if data.get(16).copied().unwrap_or(0) & 1 == 0 {
                session
                    .select_action(KitRestoreActionV2::A1Reprint)
                    .unwrap();
                let mut capsule = hex_array::<CAPSULE_BYTES>(field(PROVISIONING, "a1_capsule_hex"));
                let result = session.prepare_replacement_b(&mut capsule);
                assert_eq!(capsule, [0u8; CAPSULE_BYTES]);
                result
            } else {
                select_replacement_to_preparation(&mut session);
                session.prepare_a1_reprint(surviving_b(None), &nonce)
            };
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::RestoreModeMismatch,
                WipingReasonV2::InvalidTransition,
                0,
            )
        }
        20 => {
            let (mut session, _) = begin_session(variant, digit);
            let mut calls = 0u8;
            let error = if data.get(16).copied().unwrap_or(0) & 1 == 0 {
                prepare_replacement(&mut session, digit);
                session
                    .execute_a1_reprint(digit_key(digit), |_, _| {
                        calls += 1;
                        A1ReprintDispositionV2::Accepted
                    })
                    .err()
                    .expect("wrong execution branch")
            } else {
                prepare_a1(&mut session, &nonce, digit);
                session
                    .execute_replacement_b(digit_key(digit), |_| {
                        calls += 1;
                        KitRestoreDispositionV2::Accepted
                    })
                    .err()
                    .expect("wrong execution branch")
            };
            assert_eq!(calls, 0);
            consumed_rejection(error, KitRestoreErrorV2::RestoreModeMismatch, calls)
        }
        21 => {
            let (mut session, _) = begin_session(variant, digit);
            let result = if data.get(16).copied().unwrap_or(0) & 1 == 0 {
                prepare_replacement(&mut session, digit);
                let mut capsule = hex_array::<CAPSULE_BYTES>(field(PROVISIONING, "a1_capsule_hex"));
                let result = session.prepare_replacement_b(&mut capsule);
                assert_eq!(capsule, [0u8; CAPSULE_BYTES]);
                result
            } else {
                prepare_a1(&mut session, &nonce, digit);
                session.prepare_a1_reprint(surviving_b(None), &nonce)
            };
            rejected(
                result,
                &mut session,
                KitRestoreErrorV2::RestoreModeMismatch,
                WipingReasonV2::InvalidTransition,
                0,
            )
        }
        22 => {
            let (mut session, _) = begin_session(variant, digit);
            let selected = data.get(3).copied().unwrap_or(0) % 4;
            match selected {
                0 => {}
                1 => {
                    session
                        .select_action(KitRestoreActionV2::ReplacementB)
                        .unwrap();
                }
                2 => {
                    session
                        .select_action(KitRestoreActionV2::A1Reprint)
                        .unwrap();
                }
                _ => {
                    if data.get(16).copied().unwrap_or(0) & 1 == 0 {
                        prepare_replacement(&mut session, digit);
                    } else {
                        prepare_a1(&mut session, &nonce, digit);
                    }
                }
            }
            let screen = session.screen().expect("active drop stage");
            let summary = Summary::Dropped {
                stage: screen.stage(),
                action: screen.action(),
            };
            drop(session);
            summary
        }
        _ => unreachable!(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let Some(scenario) = selected_scenario(data) else {
        let first = fast_rejection(data);
        let second = fast_rejection(data);
        assert_eq!(first, second);
        return;
    };
    let first = run(data, scenario);
    let second = run(data, scenario);
    assert_eq!(first, second);
});
