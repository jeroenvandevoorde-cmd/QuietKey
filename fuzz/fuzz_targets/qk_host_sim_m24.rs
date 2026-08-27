#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_sim::{
    FinalizationError, FinalizedTransaction, M24SigningError, MockCardRole, MockCardSignature,
    ReviewReadyError, ReviewReadyWorkflow, TerminalInputKey, WorkflowRejection,
};
use qk_psbt::{
    canonical_serialize, parse, InputSource, IntakeError, ParseError, RejectCategory, ReviewV2Error,
};
use qk_secp::{secret_key_import, SecpError};
use std::sync::OnceLock;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_MUTATIONS: usize = 64;
const MAX_HOSTILE_DER_BYTES: usize = 256;
const FIXTURE: &[u8] = include_bytes!("../../host/qk-host-sim/tests/fixtures/m24_signing.txt");

static GOLDEN_S0: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    New,
    Intake,
    Wake,
    BeginValidation,
    Validate,
    ConstructReview,
    SignAndFinalize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    ReviewRejected {
        stage: Stage,
        error: ReviewReadyError,
    },
    SigningRejected {
        stage: Stage,
        error: M24SigningError,
    },
    Finalized {
        finalized_psbt: Vec<u8>,
        raw_transaction: Vec<u8>,
        txid: [u8; 32],
        wtxid: [u8; 32],
    },
}

struct OwnedMock {
    input_index: u32,
    role: MockCardRole,
    der_signature: Vec<u8>,
}

fn fixture_value<'a>(prefix: &[u8]) -> &'a [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("committed public fixture field")
}

fn case_value<'a>(case_name: &[u8], prefix: &[u8]) -> &'a [u8] {
    let mut active = false;
    for line in FIXTURE.split(|byte| *byte == b'\n') {
        if let Some(name) = line.strip_prefix(b"case: ") {
            active = name == case_name;
            continue;
        }
        if active {
            if let Some(value) = line.strip_prefix(prefix) {
                return value;
            }
        }
    }
    panic!("committed public fixture case field missing")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_fixture_hex(encoded: &[u8]) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "committed fixture hex width");
    let (pairs, remainder) = encoded.as_chunks::<2>();
    assert!(remainder.is_empty(), "committed fixture hex pairs");
    pairs
        .iter()
        .map(|[high, low]| {
            let high = hex_nibble(*high).expect("committed fixture high hex digit");
            let low = hex_nibble(*low).expect("committed fixture low hex digit");
            (high << 4) | low
        })
        .collect()
}

fn decode_fixture_hex_32(encoded: &[u8]) -> [u8; 32] {
    decode_fixture_hex(encoded)
        .try_into()
        .expect("committed 32-byte fixture field")
}

fn descriptor() -> DescriptorPair {
    parse_descriptor_pair(
        fixture_value(b"receive_descriptor: "),
        fixture_value(b"change_descriptor: "),
    )
    .expect("committed public descriptor pair")
}

fn golden_s0() -> &'static [u8] {
    GOLDEN_S0
        .get_or_init(|| decode_fixture_hex(fixture_value(b"initial_psbt_hex: ")))
        .as_slice()
}

fn source(selector: u8) -> InputSource {
    if selector & 4 == 0 {
        InputSource::MicroSd
    } else {
        InputSource::Qr
    }
}

fn mutation_position(high: u8, low: u8, modulus: usize) -> usize {
    ((usize::from(high) << 8) | usize::from(low)) % modulus
}

fn mutated_golden(commands: &[u8]) -> Vec<u8> {
    let mut candidate = golden_s0().to_vec();
    let (commands, _) = commands.as_chunks::<4>();
    for [operation, high, low, value] in commands.iter().take(MAX_MUTATIONS) {
        match operation % 4 {
            0 if !candidate.is_empty() => {
                let position = mutation_position(*high, *low, candidate.len());
                candidate[position] ^= *value | 1;
            }
            1 if !candidate.is_empty() => {
                let position = mutation_position(*high, *low, candidate.len());
                candidate[position] = *value;
            }
            2 if !candidate.is_empty() => {
                let position = mutation_position(*high, *low, candidate.len());
                candidate.remove(position);
            }
            3 if candidate.len() < MAX_CANDIDATE_BYTES => {
                let position = mutation_position(*high, *low, candidate.len() + 1);
                candidate.insert(position, *value);
            }
            _ => {}
        }
    }
    candidate
}

fn candidate(data: &[u8]) -> (Vec<u8>, InputSource, u8, u8, &[u8]) {
    let selector = data.first().copied().unwrap_or(0);
    let terminal_mode = data.get(1).copied().unwrap_or(0) % 5;
    let mock_mode = data.get(2).copied().unwrap_or(0) % 10;
    let remainder = data.get(3..).unwrap_or_default();
    let bytes = match selector & 3 {
        0 => golden_s0().to_vec(),
        1 => mutated_golden(remainder),
        2 => {
            let requested = remainder
                .get(..2)
                .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
                .map(u16::from_le_bytes)
                .map_or(0, usize::from);
            golden_s0()[..requested.min(golden_s0().len())].to_vec()
        }
        3 => {
            let mut bytes = golden_s0().to_vec();
            let available = MAX_CANDIDATE_BYTES.saturating_sub(bytes.len());
            bytes.extend_from_slice(
                remainder
                    .get(..remainder.len().min(available))
                    .unwrap_or_default(),
            );
            bytes
        }
        _ => unreachable!("two-bit selector is exhaustive"),
    };
    (bytes, source(selector), terminal_mode, mock_mode, remainder)
}

fn imported_terminal(input_index: u32, scalar_field: &[u8]) -> TerminalInputKey {
    let mut source = decode_fixture_hex_32(fixture_value(scalar_field));
    let secret = secret_key_import(&mut source).expect("public NEVER-FUND fixture scalar import");
    assert_eq!(source, [0u8; 32], "secret import source must be wiped");
    TerminalInputKey::new(input_index, secret)
}

fn terminal_keys(mode: u8) -> Vec<TerminalInputKey> {
    match mode {
        0 => vec![imported_terminal(0, b"role_a_route_private_scalar_hex: ")],
        1 => Vec::new(),
        2 => vec![
            imported_terminal(0, b"role_a_route_private_scalar_hex: "),
            imported_terminal(0, b"role_a_route_private_scalar_hex: "),
        ],
        3 => vec![imported_terminal(1, b"role_a_route_private_scalar_hex: ")],
        4 => vec![imported_terminal(0, b"role_b_route_private_scalar_hex: ")],
        _ => unreachable!("terminal mode modulo five is exhaustive"),
    }
}

fn owned_mock(input_index: u32, role: MockCardRole, der_signature: &[u8]) -> OwnedMock {
    OwnedMock {
        input_index,
        role,
        der_signature: der_signature.to_vec(),
    }
}

fn mock_signatures(mode: u8, hostile: &[u8]) -> Vec<OwnedMock> {
    let b = decode_fixture_hex(fixture_value(b"signature_b_der_hex: "));
    let c = decode_fixture_hex(fixture_value(b"signature_c_der_hex: "));
    match mode {
        0 => vec![owned_mock(0, MockCardRole::B, &b)],
        1 => vec![owned_mock(0, MockCardRole::C, &c)],
        2 => Vec::new(),
        3 => vec![owned_mock(
            0,
            MockCardRole::B,
            hostile
                .get(..hostile.len().min(MAX_HOSTILE_DER_BYTES))
                .unwrap_or_default(),
        )],
        4 => vec![
            owned_mock(0, MockCardRole::B, &b),
            owned_mock(0, MockCardRole::B, &b),
        ],
        5 => vec![
            owned_mock(0, MockCardRole::B, &b),
            owned_mock(0, MockCardRole::C, &b),
        ],
        6 => vec![
            owned_mock(0, MockCardRole::B, &b),
            owned_mock(0, MockCardRole::B, &c),
        ],
        7 => vec![
            owned_mock(0, MockCardRole::B, &b),
            owned_mock(0, MockCardRole::C, &c),
        ],
        8 => vec![owned_mock(1, MockCardRole::B, &b)],
        9 => vec![owned_mock(0, MockCardRole::B, &c)],
        _ => unreachable!("mock mode modulo ten is exhaustive"),
    }
}

fn reject_name(category: RejectCategory) -> &'static str {
    match category {
        RejectCategory::InputTooLarge => "InputTooLarge",
        RejectCategory::InvalidMagic => "InvalidMagic",
        RejectCategory::Truncated => "Truncated",
        RejectCategory::NonMinimalCompactSize => "NonMinimalCompactSize",
        RejectCategory::InvalidKeyStructure => "InvalidKeyStructure",
        RejectCategory::InvalidValueStructure => "InvalidValueStructure",
        RejectCategory::DuplicateKey => "DuplicateKey",
        RejectCategory::V2GlobalField => "V2GlobalField",
        RejectCategory::TaprootField => "TaprootField",
        RejectCategory::MissingUnsignedTx => "MissingUnsignedTx",
        RejectCategory::MalformedUnsignedTx => "MalformedUnsignedTx",
        RejectCategory::UnsignedTxWitnessFormat => "UnsignedTxWitnessFormat",
        RejectCategory::UnsignedTxScriptSigNotEmpty => "UnsignedTxScriptSigNotEmpty",
        RejectCategory::UnsignedTxZeroInputs => "UnsignedTxZeroInputs",
        RejectCategory::UnsignedTxZeroOutputs => "UnsignedTxZeroOutputs",
        RejectCategory::InvalidMapCount => "InvalidMapCount",
        RejectCategory::TrailingBytes => "TrailingBytes",
        RejectCategory::TooManyInputs => "TooManyInputs",
        RejectCategory::TooManyOutputs => "TooManyOutputs",
        RejectCategory::TooManySigners => "TooManySigners",
        RejectCategory::PathTooDeep => "PathTooDeep",
        RejectCategory::AllocationFailed => "AllocationFailed",
        RejectCategory::UnsupportedPsbtVersion => "UnsupportedPsbtVersion",
        RejectCategory::KeyTooLong => "KeyTooLong",
        RejectCategory::ValueTooLong => "ValueTooLong",
        RejectCategory::TooManyRecords => "TooManyRecords",
        RejectCategory::TxOutputScriptTooLong => "TxOutputScriptTooLong",
    }
}

fn assert_parse_error(error: ParseError, candidate_len: usize) {
    assert!(error.offset <= candidate_len);
    assert!(!reject_name(error.category).is_empty());
    assert!(!error.to_string().is_empty());
}

fn intake_error_name(error: IntakeError) -> &'static str {
    match error {
        IntakeError::TooLarge => "TooLarge",
        IntakeError::AllocationFailed => "AllocationFailed",
        IntakeError::HashFailure => "HashFailure",
    }
}

fn assert_review_error(error: ReviewV2Error) {
    match error {
        ReviewV2Error::SourceMismatch => {}
        ReviewV2Error::Semantic(semantic) => {
            assert!(!semantic.category.to_string().is_empty());
        }
        ReviewV2Error::FeePolicyArithmeticOverflow
        | ReviewV2Error::EmergencyFeeCeilingExceeded
        | ReviewV2Error::InputCountTooLarge
        | ReviewV2Error::OutputCountTooLarge
        | ReviewV2Error::UnsignedTransactionTooLong
        | ReviewV2Error::InputIndexMismatch
        | ReviewV2Error::OutputIndexMismatch
        | ReviewV2Error::LengthOverflow
        | ReviewV2Error::FieldLengthOverflow
        | ReviewV2Error::CanonicalTooLong
        | ReviewV2Error::AllocationFailed
        | ReviewV2Error::HashFailure
        | ReviewV2Error::InternalInvariant => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_workflow_rejection(error: WorkflowRejection) {
    match error {
        WorkflowRejection::InvalidTransition(_)
        | WorkflowRejection::MissingToken { .. }
        | WorkflowRejection::TokenMismatch { .. }
        | WorkflowRejection::CycleCounterExhausted => {}
    }
}

fn assert_review_ready_error(error: ReviewReadyError, candidate_len: usize) {
    match error {
        ReviewReadyError::Intake(error) => assert!(!intake_error_name(error).is_empty()),
        ReviewReadyError::WorkflowUnavailable
        | ReviewReadyError::Finished
        | ReviewReadyError::WorkflowInvariant
        | ReviewReadyError::ReviewMismatch
        | ReviewReadyError::ReviewHashMismatch
        | ReviewReadyError::RetainedS0Mismatch => {}
        ReviewReadyError::WorkflowRejected(error) => assert_workflow_rejection(error),
        ReviewReadyError::ValidationParse(error)
        | ReviewReadyError::ConstructionParse(error)
        | ReviewReadyError::Reparse(error) => assert_parse_error(error, candidate_len),
        ReviewReadyError::Build(error)
        | ReviewReadyError::Rebuild(error)
        | ReviewReadyError::Hash(error)
        | ReviewReadyError::Rehash(error) => assert_review_error(error),
    }
    assert!(!error.to_string().is_empty());
}

fn assert_secp_error(error: SecpError) {
    match error {
        SecpError::DerLengthOutOfBounds
        | SecpError::PubkeyParseFailed
        | SecpError::PubkeySerializeFailed
        | SecpError::TweakRejected
        | SecpError::SignatureParseFailed
        | SecpError::VerificationFailed
        | SecpError::SecretKeyRejected
        | SecpError::SigningContextUnavailable
        | SecpError::SigningFailed
        | SecpError::SignatureSerializeFailed
        | SecpError::SelfVerificationFailed
        | SecpError::ProvisioningContextUnavailable
        | SecpError::ProvisioningPublicKeyCreateFailed
        | SecpError::ProvisioningSecretTweakRejected
        | SecpError::UnknownReturnCode => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_finalization_error(error: FinalizationError) {
    match error {
        FinalizationError::CryptographicVerification(semantic) => {
            assert!(!semantic.category.to_string().is_empty());
        }
        FinalizationError::CapabilityParse
        | FinalizationError::NonCanonicalInput
        | FinalizationError::ThresholdIncomplete
        | FinalizationError::WitnessShapeMismatch
        | FinalizationError::WitnessOrderMismatch
        | FinalizationError::LengthOverflow
        | FinalizationError::ArtifactTooLarge
        | FinalizationError::AllocationFailed
        | FinalizationError::FinalizedPsbtReparse
        | FinalizationError::FinalizedPsbtNonCanonical
        | FinalizationError::ForbiddenDelta
        | FinalizationError::RawTransactionReparse
        | FinalizationError::BaseTransactionMismatch
        | FinalizationError::WitnessMismatch
        | FinalizationError::HashFailed
        | FinalizationError::InternalInvariant => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_m24_error(error: M24SigningError) {
    match error {
        M24SigningError::ReviewRebuild(error) => assert_review_error(error),
        M24SigningError::ExistingSignatureVerification(error) => {
            assert!(!error.category.to_string().is_empty());
            assert!(!error.to_string().is_empty());
        }
        M24SigningError::SerializeFailed(error) => {
            assert!(!format!("{error:?}").is_empty());
        }
        M24SigningError::TerminalSigning(error) => assert_secp_error(error),
        M24SigningError::Finalization(error) => assert_finalization_error(error),
        M24SigningError::WrongState
        | M24SigningError::RetainedS0Mismatch
        | M24SigningError::ParseFailed
        | M24SigningError::ReviewFactsMismatch
        | M24SigningError::ReviewHashMismatch
        | M24SigningError::DigestFailed
        | M24SigningError::InputOutOfRange
        | M24SigningError::DuplicateTerminalKey
        | M24SigningError::MissingTerminalKey
        | M24SigningError::UnexpectedTerminalKey
        | M24SigningError::DuplicateSignature
        | M24SigningError::DuplicateRole
        | M24SigningError::SignatureConflict
        | M24SigningError::ThresholdAlreadyMet
        | M24SigningError::ThresholdWouldBeExceeded
        | M24SigningError::ThresholdIncomplete
        | M24SigningError::TooManyInsertions
        | M24SigningError::TerminalPreInsertionVerificationFailed
        | M24SigningError::InvalidMockSignature
        | M24SigningError::ForbiddenDelta
        | M24SigningError::NonCanonicalOutput
        | M24SigningError::ArtifactTooLarge
        | M24SigningError::AllocationFailed
        | M24SigningError::FinalTransactionReparse
        | M24SigningError::WitnessOrderMismatch
        | M24SigningError::FinalSignatureVerificationFailed
        | M24SigningError::InternalInvariant => {}
    }
    assert!(!error.to_string().is_empty());
}

fn review_rejected(
    workflow: &mut ReviewReadyWorkflow,
    stage: Stage,
    error: ReviewReadyError,
    candidate_len: usize,
) -> Outcome {
    assert_review_ready_error(error, candidate_len);
    assert!(workflow.is_finished());
    assert!(workflow.review_ready().is_none());
    assert_eq!(workflow.wake(), Err(ReviewReadyError::Finished));
    Outcome::ReviewRejected { stage, error }
}

fn assert_exact_final(case_name: &[u8], finalized: &FinalizedTransaction) {
    assert_eq!(
        finalized.finalized_psbt(),
        decode_fixture_hex(case_value(case_name, b"finalized_psbt_hex: "))
    );
    assert_eq!(
        finalized.raw_transaction(),
        decode_fixture_hex(case_value(case_name, b"raw_tx_hex: "))
    );
    assert_eq!(
        finalized.txid(),
        decode_fixture_hex_32(case_value(case_name, b"txid_raw_hex: "))
    );
    assert_eq!(
        finalized.wtxid(),
        decode_fixture_hex_32(case_value(case_name, b"wtxid_raw_hex: "))
    );
}

fn run_once(
    candidate: &[u8],
    source: InputSource,
    terminal_mode: u8,
    mock_mode: u8,
    hostile_mock: &[u8],
) -> Outcome {
    let mut workflow = match ReviewReadyWorkflow::new(descriptor()) {
        Ok(workflow) => workflow,
        Err(error) => {
            assert_review_ready_error(error, candidate.len());
            return Outcome::ReviewRejected {
                stage: Stage::New,
                error,
            };
        }
    };
    let mut caller = candidate.to_vec();
    if let Err(error) = workflow.intake(&caller, source) {
        return review_rejected(&mut workflow, Stage::Intake, error, candidate.len());
    }
    caller.fill(0xa5);
    if let Err(error) = workflow.wake() {
        return review_rejected(&mut workflow, Stage::Wake, error, candidate.len());
    }
    if let Err(error) = workflow.begin_validation() {
        return review_rejected(
            &mut workflow,
            Stage::BeginValidation,
            error,
            candidate.len(),
        );
    }
    if let Err(error) = workflow.validate() {
        return review_rejected(&mut workflow, Stage::Validate, error, candidate.len());
    }
    if let Err(error) = workflow.construct_review() {
        return review_rejected(
            &mut workflow,
            Stage::ConstructReview,
            error,
            candidate.len(),
        );
    }

    let owned_mocks = mock_signatures(mock_mode, hostile_mock);
    let mocks: Vec<MockCardSignature<'_>> = owned_mocks
        .iter()
        .map(|mock| MockCardSignature {
            input_index: mock.input_index,
            role: mock.role,
            der_signature: &mock.der_signature,
        })
        .collect();
    let result = workflow.sign_and_finalize_m24(terminal_keys(terminal_mode), &mocks);
    match result {
        Err(error) => {
            assert_m24_error(error);
            // The error surface carries no artifact, signature, key, or hostile bytes.
            Outcome::SigningRejected {
                stage: Stage::SignAndFinalize,
                error,
            }
        }
        Ok(finalized) => {
            let view = parse(finalized.finalized_psbt(), source)
                .expect("released finalized PSBT must freshly parse");
            assert_eq!(
                canonical_serialize(&view).expect("released finalized PSBT must serialize"),
                finalized.finalized_psbt()
            );
            if candidate == golden_s0() && terminal_mode == 0 {
                match mock_mode {
                    0 => assert_exact_final(b"M24-A-B", &finalized),
                    1 => assert_exact_final(b"M24-A-C", &finalized),
                    _ => panic!("unexpected M24 acceptance for exact fixture controls"),
                }
            }
            Outcome::Finalized {
                finalized_psbt: finalized.finalized_psbt().to_vec(),
                raw_transaction: finalized.raw_transaction().to_vec(),
                txid: finalized.txid(),
                wtxid: finalized.wtxid(),
            }
        }
    }
}

fn assert_signing_error(outcome: &Outcome, expected: M24SigningError) {
    match outcome {
        Outcome::SigningRejected {
            stage: Stage::SignAndFinalize,
            error,
        } => assert_eq!(*error, expected),
        _ => panic!("exact public controls produced the wrong outcome"),
    }
}

fn assert_exact_control_outcome(outcome: &Outcome, terminal_mode: u8, mock_mode: u8) {
    match terminal_mode {
        0 => match mock_mode {
            0 | 1 => assert!(matches!(outcome, Outcome::Finalized { .. })),
            2 => assert_signing_error(outcome, M24SigningError::ThresholdIncomplete),
            3 => {}
            4 | 5 => assert_signing_error(outcome, M24SigningError::DuplicateSignature),
            6 => assert_signing_error(outcome, M24SigningError::DuplicateRole),
            7 => assert_signing_error(outcome, M24SigningError::ThresholdWouldBeExceeded),
            8 => assert_signing_error(outcome, M24SigningError::InputOutOfRange),
            9 => assert_signing_error(outcome, M24SigningError::InvalidMockSignature),
            _ => unreachable!("mock mode modulo ten is exhaustive"),
        },
        1 => match mock_mode {
            4 | 5 => assert_signing_error(outcome, M24SigningError::DuplicateSignature),
            8 => assert_signing_error(outcome, M24SigningError::InputOutOfRange),
            _ => assert_signing_error(outcome, M24SigningError::MissingTerminalKey),
        },
        2 => assert_signing_error(outcome, M24SigningError::DuplicateTerminalKey),
        3 => assert_signing_error(outcome, M24SigningError::InputOutOfRange),
        4 => match mock_mode {
            4 | 5 => assert_signing_error(outcome, M24SigningError::DuplicateSignature),
            8 => assert_signing_error(outcome, M24SigningError::InputOutOfRange),
            _ => assert_signing_error(
                outcome,
                M24SigningError::TerminalSigning(SecpError::SelfVerificationFailed),
            ),
        },
        _ => unreachable!("terminal mode modulo five is exhaustive"),
    }
}

fuzz_target!(|data: &[u8]| {
    let (candidate, source, terminal_mode, mock_mode, hostile_mock) = candidate(data);
    let first = run_once(&candidate, source, terminal_mode, mock_mode, hostile_mock);
    let second = run_once(&candidate, source, terminal_mode, mock_mode, hostile_mock);
    assert_eq!(first, second);
    if candidate == golden_s0() {
        assert_exact_control_outcome(&first, terminal_mode, mock_mode);
    }
});
