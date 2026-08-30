#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    kit_spend_execution_trace_v2, reset_kit_spend_execution_trace_v2,
    CoordinatorCompletenessStatementV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, KeypadKey, KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2,
    KitSpendAssertionDigitV2, KitSpendErrorV2, KitSpendExecutionTraceV2,
    KitSpendForeignOperationV2, KitSpendInterruptionV2, KitSpendSessionV2, KitSpendStageV2,
    ScreenFlowV2, ScreenKindV2, WipingReasonV2, KIT_FALLBACK_TABLE_V2,
};
use qk_psbt::{InputSource, ReplacementReceiveIndexV2};

#[allow(dead_code)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_BYTES: usize = 512;
const SCENARIOS: u8 = 28;
const FRAME_BYTES: usize = 142;
const FALLBACK_SYMBOLS: usize = 228;

const FIXTURE: &str = include_str!("../../host/qk-host-sim/tests/fixtures/kit_spend_v2.txt");
const PROVISIONING: &str =
    include_str!("../../host/qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &str = include_str!("../../host/qk-kit/tests/fixtures/kit_share_v2.txt");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Summary {
    Success {
        mode: KitInputModeV2,
        identities: [u8; 2],
        old_wallet_id: [u8; 32],
        replacement_wallet_id: [u8; 32],
        destination_index: u32,
        review_hash: [u8; 32],
        finalized_psbt_sha256: [u8; 32],
        raw_transaction_sha256: [u8; 32],
        txid: [u8; 32],
        wtxid: [u8; 32],
    },
    Validated {
        review_hash: [u8; 32],
        destination_index: u32,
    },
    Rejected {
        error: &'static str,
        terminal: Option<FlowTerminalV2>,
    },
    Dropped {
        stage: KitSpendStageV2,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedSummary {
    result: Summary,
    execution: KitSpendExecutionTraceV2,
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

fn hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value).try_into().expect("registered fixed width")
}

fn reference_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = reference_sha256::Sha256::new();
    hasher.update(bytes).expect("bounded public artifact");
    hasher.finalize().expect("bounded public artifact digest")
}

fn receive_index(raw: u32) -> ReplacementReceiveIndexV2 {
    ReplacementReceiveIndexV2::from_untrusted(raw)
}

fn old_descriptors() -> [[u8; 306]; 2] {
    [
        field(FIXTURE, "old_receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("registered receive descriptor width"),
        field(FIXTURE, "old_change_descriptor")
            .as_bytes()
            .try_into()
            .expect("registered change descriptor width"),
    ]
}

fn replacement_descriptors() -> [[u8; 306]; 2] {
    [
        field(FIXTURE, "replacement_receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("registered replacement receive width"),
        field(FIXTURE, "replacement_change_descriptor")
            .as_bytes()
            .try_into()
            .expect("registered replacement change width"),
    ]
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
    digit_key(u8::try_from(number).expect("bounded fallback coordinate"))
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

fn compact_size(output: &mut Vec<u8>, value: usize) {
    match value {
        0..=0xfc => output.push(value as u8),
        0xfd..=0xffff => {
            output.push(0xfd);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        _ => {
            output.push(0xfe);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
    }
}

fn record(output: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    compact_size(output, key.len());
    output.extend_from_slice(key);
    compact_size(output, value.len());
    output.extend_from_slice(value);
}

fn previous_transaction(variant: u8) -> Vec<u8> {
    let mut previous = hex_vec(field(FIXTURE, "previous_transaction_hex"));
    let last = previous.len() - 1;
    previous[last] = variant;
    previous
}

fn previous_txid_wire(variant: u8) -> [u8; 32] {
    let first = reference_hash(&previous_transaction(variant));
    let wire = reference_hash(&first);
    if variant == 0 {
        assert_eq!(wire, hex_array(field(FIXTURE, "previous_txid_wire_hex")));
    }
    wire
}

fn input_map(foreign: bool, invalid_partial: bool, previous_variant: u8) -> Vec<u8> {
    let previous = previous_transaction(previous_variant);
    let old_script = hex_vec(field(FIXTURE, "old_script_pubkey_hex"));
    let pub_a = hex_array::<33>(field(FIXTURE, "old_role_a_route_public_key_hex"));
    let pub_b = hex_array::<33>(field(FIXTURE, "old_role_b_route_public_key_hex"));
    let mut fingerprint_a = hex_array::<4>(field(FIXTURE, "old_role_a_fingerprint_hex"));
    if foreign {
        fingerprint_a[0] ^= 0x80;
    }
    let fingerprint_b = hex_array::<4>(field(FIXTURE, "old_role_b_fingerprint_hex"));
    let path = [0x8000_0030u32, 0x8000_0000, 0x8000_0000, 0x8000_0002, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let mut witness_utxo = 1_000_000u64.to_le_bytes().to_vec();
    compact_size(&mut witness_utxo, old_script.len());
    witness_utxo.extend_from_slice(&old_script);
    let mut output = Vec::new();
    record(&mut output, &[0], &previous);
    record(&mut output, &[1], &witness_utxo);
    if invalid_partial {
        let mut signature = hex_vec(field(FIXTURE, "role_a_der_hex"));
        let last = signature.len() - 1;
        signature[last] ^= 1;
        signature.push(1);
        let mut key = vec![2];
        key.extend_from_slice(&pub_a);
        record(&mut output, &key, &signature);
    }
    record(&mut output, &[3], &1u32.to_le_bytes());
    let mut key_a = vec![6];
    key_a.extend_from_slice(&pub_a);
    let mut value_a = fingerprint_a.to_vec();
    value_a.extend_from_slice(&path);
    record(&mut output, &key_a, &value_a);
    let mut key_b = vec![6];
    key_b.extend_from_slice(&pub_b);
    let mut value_b = fingerprint_b.to_vec();
    value_b.extend_from_slice(&path);
    record(&mut output, &key_b, &value_b);
    output.push(0);
    output
}

fn unsigned_transaction(input_count: usize, outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut transaction = 2u32.to_le_bytes().to_vec();
    compact_size(&mut transaction, input_count);
    for index in 0..input_count {
        transaction.extend_from_slice(&previous_txid_wire(
            u8::try_from(index).expect("bounded fuzz input count"),
        ));
        transaction.extend_from_slice(&0u32.to_le_bytes());
        transaction.push(0);
        transaction.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
    }
    compact_size(&mut transaction, outputs.len());
    for (amount, script) in outputs {
        transaction.extend_from_slice(&amount.to_le_bytes());
        compact_size(&mut transaction, script.len());
        transaction.extend_from_slice(script);
    }
    transaction.extend_from_slice(&500_000u32.to_le_bytes());
    transaction
}

fn constructed_s0(
    input_count: usize,
    outputs: Vec<(u64, Vec<u8>)>,
    foreign_input: Option<usize>,
    invalid_partial: bool,
) -> Vec<u8> {
    let transaction = unsigned_transaction(input_count, &outputs);
    let mut psbt = b"psbt\xff".to_vec();
    record(&mut psbt, &[0], &transaction);
    psbt.push(0);
    for index in 0..input_count {
        psbt.extend_from_slice(&input_map(
            foreign_input == Some(index),
            invalid_partial,
            u8::try_from(index).expect("bounded fuzz input count"),
        ));
    }
    psbt.extend(std::iter::repeat(0).take(outputs.len()));
    psbt
}

fn old_change_s0() -> Vec<u8> {
    let change_script = hex_vec(field(PROVISIONING, "change_0_script_pubkey"));
    let transaction = unsigned_transaction(1, &[(900_000, change_script)]);
    let mut psbt = b"psbt\xff".to_vec();
    record(&mut psbt, &[0], &transaction);
    psbt.push(0);
    psbt.extend_from_slice(&input_map(false, false, 0));
    let path = [0x8000_0030u32, 0x8000_0000, 0x8000_0000, 0x8000_0002, 1, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    for (pubkey_field, fingerprint_field) in [
        ("change_0_role_a_pubkey", "old_role_a_fingerprint_hex"),
        ("change_0_role_b_pubkey", "old_role_b_fingerprint_hex"),
    ] {
        let mut key = vec![2];
        key.extend_from_slice(&hex_array::<33>(field(PROVISIONING, pubkey_field)));
        let mut value = hex_array::<4>(field(FIXTURE, fingerprint_field)).to_vec();
        value.extend_from_slice(&path);
        record(&mut psbt, &key, &value);
    }
    psbt.push(0);
    psbt
}

fn destination_script() -> Vec<u8> {
    hex_vec(field(FIXTURE, "destination_script_pubkey_hex"))
}

fn base_s0() -> Vec<u8> {
    let built = constructed_s0(1, vec![(900_000, destination_script())], None, false);
    assert_eq!(built, hex_vec(field(FIXTURE, "s0_hex")));
    built
}

fn begin_session(
    door: KitDoorV2,
    variant: u8,
    digit: u8,
) -> Result<KitSpendSessionV2, KitSpendErrorV2> {
    KitSpendSessionV2::begin(
        intake_ready(door, variant),
        &old_descriptors(),
        KitSpendAssertionDigitV2::new(digit)?,
    )
}

fn assert_initial(session: &KitSpendSessionV2, variant: u8) {
    let screen = session.screen().expect("active transaction screen");
    assert_eq!(screen.stage(), KitSpendStageV2::TransactionIntake);
    assert_eq!(
        screen.old_wallet_id(),
        hex_array(field(FIXTURE, "old_wallet_id_hex"))
    );
    assert_eq!(screen.replacement_wallet_id(), None);
    assert_eq!(screen.destination_index(), None);
    assert_eq!(screen.review_hash(), None);
    assert_eq!(
        screen.input_mode(),
        if variant & 2 == 0 {
            KitInputModeV2::Scanner
        } else {
            KitInputModeV2::Fallback
        }
    );
}

fn expected_identities(variant: u8) -> [u8; 2] {
    if variant & 1 == 0 {
        [1, 2]
    } else {
        [2, 1]
    }
}

fn complete(
    mut session: KitSpendSessionV2,
    mut psbt: Vec<u8>,
    replacement: &[[u8; 306]; 2],
    destination_index: u32,
    digit: u8,
    variant: u8,
    source: InputSource,
    exact_review: bool,
) -> Summary {
    let validation = session
        .submit_sweep(
            &mut psbt,
            source,
            replacement,
            receive_index(destination_index),
        )
        .expect("registered sweep validation");
    assert!(psbt.iter().all(|byte| *byte == 0));
    assert_eq!(validation.stage(), KitSpendStageV2::CompletenessStatement);
    assert_eq!(
        validation.replacement_wallet_id(),
        Some(hex_array(field(FIXTURE, "replacement_wallet_id_hex")))
    );
    assert_eq!(validation.destination_index(), Some(destination_index));
    let review_hash = validation.review_hash().expect("validated review hash");
    if exact_review {
        assert_eq!(review_hash, hex_array(field(FIXTURE, "review_hash_hex")));
    }
    let assertion = session
        .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("completeness statement");
    assert_eq!(assertion.stage(), KitSpendStageV2::HumanAssertion);
    assert_eq!(
        assertion.assertion_digit().map(|value| value.value()),
        Some(digit)
    );
    let identities = session
        .frame_identities()
        .map(|identity| identity.share_index().as_u8());
    assert_eq!(identities, expected_identities(variant));
    let outcome = session
        .execute(digit_key(digit))
        .expect("matching assertion must finalize one sweep");
    assert_eq!(
        outcome.completeness(),
        CoordinatorCompletenessStatementV2::AllFundsIncluded
    );
    assert_eq!(outcome.review_hash(), review_hash);
    assert_eq!(outcome.destination_index(), destination_index);
    let finalized = outcome.finalized();
    assert_eq!(
        finalized.finalized_psbt(),
        hex_vec(field(FIXTURE, "finalized_psbt_hex"))
    );
    assert_eq!(
        finalized.raw_transaction(),
        hex_vec(field(FIXTURE, "raw_transaction_hex"))
    );
    assert_eq!(finalized.txid(), hex_array(field(FIXTURE, "txid_raw_hex")));
    assert_eq!(
        finalized.wtxid(),
        hex_array(field(FIXTURE, "wtxid_raw_hex"))
    );
    Summary::Success {
        mode: if variant & 2 == 0 {
            KitInputModeV2::Scanner
        } else {
            KitInputModeV2::Fallback
        },
        identities,
        old_wallet_id: outcome.old_wallet_id(),
        replacement_wallet_id: outcome.replacement_wallet_id(),
        destination_index,
        review_hash,
        finalized_psbt_sha256: reference_hash(finalized.finalized_psbt()),
        raw_transaction_sha256: reference_hash(finalized.raw_transaction()),
        txid: finalized.txid(),
        wtxid: finalized.wtxid(),
    }
}

fn constructor_rejection(error: KitSpendErrorV2, expected: &'static str) -> Summary {
    assert_eq!(error.name(), expected);
    assert_eq!(error.to_string(), expected);
    Summary::Rejected {
        error: error.name(),
        terminal: None,
    }
}

fn rejected<T>(
    result: Result<T, KitSpendErrorV2>,
    session: &mut KitSpendSessionV2,
    expected: &'static str,
    reason: WipingReasonV2,
) -> Summary {
    let error = result.err().expect("scenario must reject");
    assert_eq!(error.name(), expected);
    assert_eq!(error.to_string(), expected);
    assert_eq!(session.failure(), Some(error));
    let terminal = Some(FlowTerminalV2::FailedWiped(reason));
    assert_eq!(session.terminal(), terminal);
    assert_eq!(session.screen(), None);
    assert_eq!(
        session.interrupt(KitSpendInterruptionV2::SessionTimeout),
        Err(KitSpendErrorV2::Finished)
    );
    Summary::Rejected {
        error: error.name(),
        terminal,
    }
}

fn consumed_rejection(error: KitSpendErrorV2, expected: &'static str) -> Summary {
    constructor_rejection(error, expected)
}

fn prepare_to_completeness(session: &mut KitSpendSessionV2, psbt: &mut [u8]) {
    let screen = session
        .submit_sweep(
            psbt,
            InputSource::MicroSd,
            &replacement_descriptors(),
            receive_index(0),
        )
        .expect("registered sweep");
    assert!(psbt.iter().all(|byte| *byte == 0));
    assert_eq!(screen.stage(), KitSpendStageV2::CompletenessStatement);
}

fn prepare_to_assertion(session: &mut KitSpendSessionV2, psbt: &mut [u8]) {
    prepare_to_completeness(session, psbt);
    assert_eq!(
        session
            .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
            .expect("registered completeness")
            .stage(),
        KitSpendStageV2::HumanAssertion
    );
}

fn selector(data: &[u8]) -> u8 {
    data.iter()
        .fold(0x71u8, |state, byte| state.wrapping_mul(33) ^ byte)
}

fn selected_scenario(data: &[u8]) -> Option<u8> {
    if selector(data) != 0 {
        return None;
    }
    let scenario = data.first().copied()?.checked_sub(b'K')?;
    (scenario < SCENARIOS).then_some(scenario)
}

fn fast_rejection(data: &[u8]) -> Summary {
    let invalid = 10 + data.get(3).copied().unwrap_or(0) % 246;
    let error = KitSpendAssertionDigitV2::new(invalid)
        .err()
        .expect("out-of-range digit must reject");
    constructor_rejection(error, "InvalidHumanAssertionDigit")
}

fn hostile_psbt(data: &[u8]) -> Vec<u8> {
    let mode = data.get(3).copied().unwrap_or(0) % 4;
    let hostile = data.get(4..).unwrap_or_default();
    match mode {
        0 => hostile.to_vec(),
        1 => {
            let mut bytes = base_s0();
            let cut = hostile.iter().fold(0usize, |value, byte| {
                value.wrapping_mul(257).wrapping_add(usize::from(*byte))
            }) % bytes.len();
            bytes.truncate(cut);
            bytes
        }
        2 => {
            let mut bytes = base_s0();
            if hostile.is_empty() {
                bytes[0] ^= 1;
            } else {
                for (offset, byte) in hostile.iter().enumerate() {
                    let index = (offset.wrapping_mul(257) + usize::from(*byte)) % bytes.len();
                    bytes[index] ^= *byte | 1;
                }
            }
            bytes
        }
        _ => {
            let mut bytes = base_s0();
            if hostile.is_empty() {
                bytes.push(0xff);
            } else {
                bytes.extend_from_slice(hostile);
            }
            bytes
        }
    }
}

fn run(data: &[u8], scenario: u8) -> Summary {
    let variant = data.get(1).copied().unwrap_or(0) % 4;
    let digit = data.get(2).copied().unwrap_or(0) % 10;
    match scenario {
        0 => {
            let session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            assert_initial(&session, variant);
            complete(
                session,
                base_s0(),
                &replacement_descriptors(),
                0,
                digit,
                variant,
                InputSource::MicroSd,
                true,
            )
        }
        1 => {
            let error = begin_session(KitDoorV2::KitRestore, variant, digit)
                .err()
                .expect("wrong door");
            constructor_rejection(error, "WrongDoor")
        }
        2 => {
            let mut wrong = old_descriptors();
            let branch = usize::from(data.get(4).copied().unwrap_or(0)) % wrong.len();
            let offset = data
                .get(3..)
                .unwrap_or_default()
                .iter()
                .fold(0usize, |value, byte| {
                    value.wrapping_mul(257).wrapping_add(usize::from(*byte))
                })
                % wrong[branch].len();
            wrong[branch][offset] ^= 1;
            let error = KitSpendSessionV2::begin(
                intake_ready(KitDoorV2::KitSpend, variant),
                &wrong,
                KitSpendAssertionDigitV2::new(digit).unwrap(),
            )
            .err()
            .expect("mismatched recovered wallet");
            constructor_rejection(error, "RecoveredWalletMismatch")
        }
        3 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut replacement = replacement_descriptors();
            replacement[0][0] ^= 1;
            let mut psbt = base_s0();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement,
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "ReplacementDescriptorInvalid",
                WipingReasonV2::OperationFailed,
            )
        }
        4 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(65_536),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "DestinationIndexOutOfRange",
                WipingReasonV2::OperationFailed,
            )
        }
        5 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &old_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "ReplacementWalletUnchanged",
                WipingReasonV2::OperationFailed,
            )
        }
        6 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(1),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "DestinationMismatch",
                WipingReasonV2::OperationFailed,
            )
        }
        7 | 8 => {
            let outputs = if scenario == 7 {
                Vec::new()
            } else {
                vec![
                    (450_000, destination_script()),
                    (450_000, destination_script()),
                ]
            };
            let mut psbt = constructed_s0(1, outputs, None, false);
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "OutputCountNotOne",
                WipingReasonV2::OperationFailed,
            )
        }
        9 | 10 => {
            let mut psbt = if scenario == 9 {
                constructed_s0(
                    1,
                    vec![(900_000, hex_vec(field(FIXTURE, "old_script_pubkey_hex")))],
                    None,
                    false,
                )
            } else {
                old_change_s0()
            };
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            let expected = if scenario == 9 {
                "OldWalletDestination"
            } else {
                "ChangeOutputProhibited"
            };
            rejected(
                result,
                &mut session,
                expected,
                WipingReasonV2::OperationFailed,
            )
        }
        11 | 12 | 13 => {
            let script = match scenario {
                11 => hex_vec("6a03aabbcc"),
                12 => hex_vec(&format!("0014{}", "11".repeat(20))),
                _ => hex_vec(&format!("5120{}", "22".repeat(32))),
            };
            let amount = if scenario == 11 { 0 } else { 900_000 };
            let mut psbt = constructed_s0(1, vec![(amount, script)], None, false);
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "DestinationTypeMismatch",
                WipingReasonV2::OperationFailed,
            )
        }
        14 => {
            let mut wrong = destination_script();
            wrong[2 + usize::from(data.get(3).copied().unwrap_or(0)) % 32] ^= 1;
            let mut psbt = constructed_s0(1, vec![(900_000, wrong)], None, false);
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "DestinationMismatch",
                WipingReasonV2::OperationFailed,
            )
        }
        15 => {
            let mut psbt = constructed_s0(1, vec![(900_000, destination_script())], None, true);
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "ExistingSignatureVerificationFailed",
                WipingReasonV2::OperationFailed,
            )
        }
        16 => {
            let foreign = usize::from(data.get(3).copied().unwrap_or(0)) % 3;
            let mut psbt = constructed_s0(
                3,
                vec![(2_900_000, destination_script())],
                Some(foreign),
                false,
            );
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "TransactionReviewRejected",
                WipingReasonV2::OperationFailed,
            )
        }
        17 => {
            let session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            consumed_rejection(
                session
                    .execute(digit_key(digit))
                    .err()
                    .expect("missing statement"),
                "CompletenessStatementMissing",
            )
        }
        18 | 19 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            prepare_to_assertion(&mut session, &mut psbt);
            let key = if scenario == 18 {
                digit_key((digit + 1) % 10)
            } else {
                KeypadKey::CancelBack
            };
            let expected = if scenario == 18 {
                "HumanAssertionMismatch"
            } else {
                "Cancelled"
            };
            consumed_rejection(
                session.execute(key).err().expect("wrong assertion"),
                expected,
            )
        }
        20 => {
            let stage = data.get(3).copied().unwrap_or(0) % 3;
            let selected = data.get(4).copied().unwrap_or(0) % 8;
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            if stage >= 1 {
                prepare_to_completeness(&mut session, &mut psbt);
            }
            if stage == 2 {
                session
                    .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
                    .unwrap();
            }
            let (event, name, reason) = match selected {
                0 => (
                    KitSpendInterruptionV2::Cancelled,
                    "Cancelled",
                    WipingReasonV2::Cancelled,
                ),
                1 => (
                    KitSpendInterruptionV2::OperationFailed,
                    "OperationFailed",
                    WipingReasonV2::OperationFailed,
                ),
                2 => (
                    KitSpendInterruptionV2::MediaRemoved,
                    "MediaRemoved",
                    WipingReasonV2::MediaRemoved,
                ),
                3 => (
                    KitSpendInterruptionV2::CardRemoved,
                    "CardRemoved",
                    WipingReasonV2::CardRemoved,
                ),
                4 => (
                    KitSpendInterruptionV2::SessionTimeout,
                    "SessionTimeout",
                    WipingReasonV2::SessionTimeout,
                ),
                5 => (
                    KitSpendInterruptionV2::Shutdown,
                    "Shutdown",
                    WipingReasonV2::Shutdown,
                ),
                6 => (
                    KitSpendInterruptionV2::Restart,
                    "Restart",
                    WipingReasonV2::Restart,
                ),
                _ => (
                    KitSpendInterruptionV2::PowerLoss,
                    "PowerLoss",
                    WipingReasonV2::PowerLoss,
                ),
            };
            let result = session.interrupt(event);
            rejected(result, &mut session, name, reason)
        }
        21 => {
            let selected = data.get(3).copied().unwrap_or(0) % 11;
            let stage = data.get(4).copied().unwrap_or(0) % 3;
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            if stage >= 1 {
                prepare_to_completeness(&mut session, &mut psbt);
            }
            if stage == 2 {
                session
                    .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
                    .unwrap();
            }
            let (operation, name, reason) = match selected {
                0 => (
                    KitSpendForeignOperationV2::Signing,
                    "SigningOutsideSweep",
                    WipingReasonV2::OperationFailed,
                ),
                1 => (
                    KitSpendForeignOperationV2::Transaction,
                    "TransactionOutsideSweep",
                    WipingReasonV2::OperationFailed,
                ),
                2 => (
                    KitSpendForeignOperationV2::Review,
                    "ReviewOutsideSweep",
                    WipingReasonV2::OperationFailed,
                ),
                3 => (
                    KitSpendForeignOperationV2::Approval,
                    "ApprovalProhibited",
                    WipingReasonV2::OperationFailed,
                ),
                4 => (
                    KitSpendForeignOperationV2::Export,
                    "ExportProhibited",
                    WipingReasonV2::OperationFailed,
                ),
                5 => (
                    KitSpendForeignOperationV2::Intake,
                    "ForeignInputProhibited",
                    WipingReasonV2::KitScannerModeMismatch,
                ),
                6 => (
                    KitSpendForeignOperationV2::NormalWallet,
                    "NormalWalletOperationProhibited",
                    WipingReasonV2::OperationFailed,
                ),
                7 => (
                    KitSpendForeignOperationV2::Restore,
                    "RestoreProhibited",
                    WipingReasonV2::OperationFailed,
                ),
                8 => (
                    KitSpendForeignOperationV2::KitGeneration,
                    "KitGenerationProhibited",
                    WipingReasonV2::OperationFailed,
                ),
                9 => (
                    KitSpendForeignOperationV2::KitRegeneration,
                    "KitRegenerationProhibited",
                    WipingReasonV2::OperationFailed,
                ),
                _ => (
                    KitSpendForeignOperationV2::DoorSwitch,
                    "DoorSwitchAttempt",
                    WipingReasonV2::DoorSwitchAttempt,
                ),
            };
            let result = session.reject_foreign_operation(operation);
            rejected(result, &mut session, name, reason)
        }
        22 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut first = base_s0();
            prepare_to_completeness(&mut session, &mut first);
            let mut second = base_s0();
            let result = session.submit_sweep(
                &mut second,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(second.iter().all(|byte| *byte == 0));
            rejected(
                result,
                &mut session,
                "TransactionOutsideSweep",
                WipingReasonV2::OperationFailed,
            )
        }
        23 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let result =
                session.confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded);
            rejected(
                result,
                &mut session,
                "CompletenessStatementMissing",
                WipingReasonV2::OperationFailed,
            )
        }
        24 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            prepare_to_assertion(&mut session, &mut psbt);
            let result =
                session.confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded);
            rejected(
                result,
                &mut session,
                "InvalidTransition",
                WipingReasonV2::InvalidTransition,
            )
        }
        25 => {
            let stage = data.get(3).copied().unwrap_or(0) % 3;
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = base_s0();
            if stage >= 1 {
                prepare_to_completeness(&mut session, &mut psbt);
            }
            if stage == 2 {
                session
                    .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
                    .unwrap();
            }
            let stage = session.screen().expect("active drop stage").stage();
            drop(session);
            Summary::Dropped { stage }
        }
        26 => {
            let session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            complete(
                session,
                base_s0(),
                &replacement_descriptors(),
                0,
                digit,
                variant,
                InputSource::Qr,
                false,
            )
        }
        27 => {
            let mut session = begin_session(KitDoorV2::KitSpend, variant, digit).unwrap();
            let mut psbt = hostile_psbt(data);
            let result = session.submit_sweep(
                &mut psbt,
                InputSource::MicroSd,
                &replacement_descriptors(),
                receive_index(0),
            );
            assert!(psbt.iter().all(|byte| *byte == 0));
            match result {
                Ok(screen) => {
                    assert_eq!(screen.stage(), KitSpendStageV2::CompletenessStatement);
                    assert_eq!(session.failure(), None);
                    assert_eq!(session.terminal(), None);
                    Summary::Validated {
                        review_hash: screen.review_hash().expect("validated review hash"),
                        destination_index: screen
                            .destination_index()
                            .expect("validated destination index"),
                    }
                }
                Err(error) => {
                    assert_eq!(error.to_string(), error.name());
                    assert_eq!(session.failure(), Some(error));
                    let terminal = session.terminal();
                    assert!(matches!(terminal, Some(FlowTerminalV2::FailedWiped(_))));
                    assert_eq!(session.screen(), None);
                    Summary::Rejected {
                        error: error.name(),
                        terminal,
                    }
                }
            }
        }
        _ => unreachable!(),
    }
}

fn observed_run(data: &[u8], scenario: Option<u8>) -> ObservedSummary {
    reset_kit_spend_execution_trace_v2();
    let result = scenario.map_or_else(|| fast_rejection(data), |selected| run(data, selected));
    let execution = kit_spend_execution_trace_v2();
    assert_eq!(execution.callback_count, 0);
    match result {
        Summary::Success { .. } => {
            assert_eq!(execution.sign_count, 1);
            assert_eq!(execution.finalize_count, 1);
            assert_eq!(execution.terminal, Some(FlowTerminalV2::CompletedWiped));
        }
        Summary::Rejected { error, terminal } => {
            assert_eq!(execution.sign_count, 0);
            assert_eq!(execution.finalize_count, 0);
            if let Some(expected) = terminal {
                assert_eq!(execution.terminal, Some(expected));
            } else if error == "InvalidHumanAssertionDigit" {
                assert_eq!(execution.terminal, None);
            } else {
                assert!(matches!(
                    execution.terminal,
                    Some(FlowTerminalV2::FailedWiped(_))
                ));
            }
        }
        Summary::Validated { .. } | Summary::Dropped { .. } => {
            assert_eq!(execution.sign_count, 0);
            assert_eq!(execution.finalize_count, 0);
            assert_eq!(
                execution.terminal,
                Some(FlowTerminalV2::FailedWiped(WipingReasonV2::Cancelled))
            );
        }
    }
    ObservedSummary { result, execution }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let scenario = selected_scenario(data);
    let first = observed_run(data, scenario);
    let second = observed_run(data, scenario);
    assert_eq!(first, second);
});
