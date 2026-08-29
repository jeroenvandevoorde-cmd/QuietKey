#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_host_sim::{
    FinalizationV2Error, FinalizedTransaction, MockCardBSignature, ReviewReadyV3Error,
    ReviewReadyV3Workflow, SigningV2Error, TerminalInputKeyV2, WorkflowRejection,
};
use qk_psbt::{
    canonical_serialize, parse, InputSource, IntakeError, ParseError, RejectCategory,
    ReviewV3Error, FEE_POLICY_V2_IDENTIFIER, REVIEW_V3_SCHEMA_VERSION,
};
use qk_secp::{secret_key_import, SecpError};
use std::sync::OnceLock;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_MUTATIONS: usize = 64;
const MAX_HOSTILE_DER_BYTES: usize = 256;
const DESCRIPTOR_FIXTURE: &[u8] =
    include_bytes!("../../host/qk-descriptor/tests/fixtures/descriptor_pairs.txt");
const FIXTURE: &[u8] =
    include_bytes!("../../host/qk-psbt/tests/fixtures/signing_finalization_v2.txt");

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateExpectation {
    MustReject,
    ExactGolden,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    ReviewRejected {
        stage: Stage,
        error: ReviewReadyV3Error,
    },
    SigningRejected {
        stage: Stage,
        error: SigningV2Error,
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
    der_signature: Vec<u8>,
}

fn fixture_value<'a>(prefix: &[u8]) -> &'a [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("committed public fixture field")
}

fn descriptor_value<'a>(prefix: &[u8]) -> &'a [u8] {
    DESCRIPTOR_FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("committed public descriptor fixture field")
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

fn descriptor() -> DescriptorPairV2 {
    parse_descriptor_pair_v2(
        descriptor_value(b"receive: "),
        descriptor_value(b"change: "),
    )
    .expect("committed public v2 descriptor pair")
}

fn golden_s0() -> &'static [u8] {
    GOLDEN_S0
        .get_or_init(|| decode_fixture_hex(fixture_value(b"s0_hex: ")))
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

fn candidate(data: &[u8]) -> (Vec<u8>, InputSource, u8, u8, &[u8], CandidateExpectation) {
    let selector = data.first().copied().unwrap_or(0);
    let terminal_mode = data.get(1).copied().unwrap_or(0) % 5;
    let mock_mode = data.get(2).copied().unwrap_or(0) % 7;
    let remainder = data.get(3..).unwrap_or_default();
    let (bytes, expectation) = match selector & 3 {
        0 => (golden_s0().to_vec(), CandidateExpectation::ExactGolden),
        1 => {
            let bytes = mutated_golden(remainder);
            let expectation = if bytes == golden_s0() {
                CandidateExpectation::ExactGolden
            } else {
                CandidateExpectation::Unknown
            };
            (bytes, expectation)
        }
        2 => {
            let requested = remainder
                .get(..2)
                .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
                .map(u16::from_le_bytes)
                .map_or(0, usize::from);
            let length = requested.min(golden_s0().len());
            let expectation = if length == golden_s0().len() {
                CandidateExpectation::ExactGolden
            } else {
                CandidateExpectation::MustReject
            };
            (golden_s0()[..length].to_vec(), expectation)
        }
        3 => {
            let mut bytes = golden_s0().to_vec();
            let available = MAX_CANDIDATE_BYTES.saturating_sub(bytes.len());
            bytes.extend_from_slice(
                remainder
                    .get(..remainder.len().min(available))
                    .unwrap_or_default(),
            );
            let expectation = if bytes.len() == golden_s0().len() {
                CandidateExpectation::ExactGolden
            } else {
                CandidateExpectation::MustReject
            };
            (bytes, expectation)
        }
        _ => unreachable!("two-bit selector is exhaustive"),
    };
    (
        bytes,
        source(selector),
        terminal_mode,
        mock_mode,
        remainder,
        expectation,
    )
}

fn imported_terminal(input_index: u32, scalar_field: &[u8]) -> TerminalInputKeyV2 {
    let mut source = decode_fixture_hex_32(fixture_value(scalar_field));
    let secret = secret_key_import(&mut source).expect("public NEVER-FUND fixture scalar import");
    assert_eq!(source, [0u8; 32], "secret import source must be wiped");
    TerminalInputKeyV2::new(input_index, secret)
}

fn terminal_keys(mode: u8) -> Vec<TerminalInputKeyV2> {
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

fn owned_mock(input_index: u32, der_signature: &[u8]) -> OwnedMock {
    OwnedMock {
        input_index,
        der_signature: der_signature.to_vec(),
    }
}

fn mock_signatures(mode: u8, hostile: &[u8]) -> Vec<OwnedMock> {
    let b = decode_fixture_hex(fixture_value(b"role_b_der_hex: "));
    let a = decode_fixture_hex(fixture_value(b"role_a_der_hex: "));
    match mode {
        0 => vec![owned_mock(0, &b)],
        1 => Vec::new(),
        2 => vec![owned_mock(
            0,
            hostile
                .get(..hostile.len().min(MAX_HOSTILE_DER_BYTES))
                .unwrap_or_default(),
        )],
        3 => vec![owned_mock(0, &b), owned_mock(0, &b)],
        4 => vec![owned_mock(0, &b), owned_mock(0, &a)],
        5 => vec![owned_mock(1, &b)],
        6 => vec![owned_mock(0, &a)],
        _ => unreachable!("mock mode modulo seven is exhaustive"),
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

fn assert_review_error(error: ReviewV3Error) {
    match error {
        ReviewV3Error::SourceMismatch => {}
        ReviewV3Error::Semantic(semantic) => {
            assert!(!semantic.category.to_string().is_empty());
        }
        ReviewV3Error::FeePolicyArithmeticOverflow
        | ReviewV3Error::EmergencyFeeCeilingExceeded
        | ReviewV3Error::InputCountTooLarge
        | ReviewV3Error::OutputCountTooLarge
        | ReviewV3Error::UnsignedTransactionTooLong
        | ReviewV3Error::InputIndexMismatch
        | ReviewV3Error::OutputIndexMismatch
        | ReviewV3Error::LengthOverflow
        | ReviewV3Error::FieldLengthOverflow
        | ReviewV3Error::CanonicalTooLong
        | ReviewV3Error::AllocationFailed
        | ReviewV3Error::HashFailure
        | ReviewV3Error::UnsupportedReviewSchemaVersion
        | ReviewV3Error::CanonicalReviewMismatch
        | ReviewV3Error::InternalInvariant => {}
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

fn assert_review_ready_error(error: ReviewReadyV3Error, candidate_len: usize) {
    match error {
        ReviewReadyV3Error::Intake(error) => assert!(!intake_error_name(error).is_empty()),
        ReviewReadyV3Error::WorkflowUnavailable
        | ReviewReadyV3Error::Finished
        | ReviewReadyV3Error::WorkflowInvariant
        | ReviewReadyV3Error::ReviewMismatch
        | ReviewReadyV3Error::ReviewHashMismatch
        | ReviewReadyV3Error::RetainedS0Mismatch => {}
        ReviewReadyV3Error::WorkflowRejected(error) => assert_workflow_rejection(error),
        ReviewReadyV3Error::ValidationParse(error)
        | ReviewReadyV3Error::ConstructionParse(error)
        | ReviewReadyV3Error::Reparse(error) => assert_parse_error(error, candidate_len),
        ReviewReadyV3Error::Build(error)
        | ReviewReadyV3Error::Rebuild(error)
        | ReviewReadyV3Error::Hash(error)
        | ReviewReadyV3Error::Rehash(error) => assert_review_error(error),
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

fn assert_finalization_error(error: FinalizationV2Error) {
    match error {
        FinalizationV2Error::CryptographicVerification(semantic) => {
            assert!(!semantic.category.to_string().is_empty());
        }
        FinalizationV2Error::CapabilityParse
        | FinalizationV2Error::NonCanonicalInput
        | FinalizationV2Error::ReviewFactsMismatch
        | FinalizationV2Error::ThresholdIncomplete
        | FinalizationV2Error::WitnessShapeMismatch
        | FinalizationV2Error::WitnessOrderMismatch
        | FinalizationV2Error::LengthOverflow
        | FinalizationV2Error::ArtifactTooLarge
        | FinalizationV2Error::AllocationFailed
        | FinalizationV2Error::FinalizedPsbtReparse
        | FinalizationV2Error::FinalizedPsbtNonCanonical
        | FinalizationV2Error::ForbiddenDelta
        | FinalizationV2Error::RawTransactionReparse
        | FinalizationV2Error::BaseTransactionMismatch
        | FinalizationV2Error::WitnessMismatch
        | FinalizationV2Error::FinalSignatureVerificationFailed
        | FinalizationV2Error::HashFailed
        | FinalizationV2Error::InternalInvariant => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_signing_error_named(error: SigningV2Error) {
    match error {
        SigningV2Error::ReviewRebuild(error) => assert_review_error(error),
        SigningV2Error::ExistingSignatureVerification(error) => {
            assert!(!error.category.to_string().is_empty());
            assert!(!error.to_string().is_empty());
        }
        SigningV2Error::SerializeFailed(error) => {
            assert!(!format!("{error:?}").is_empty());
        }
        SigningV2Error::TerminalSigning(error) => assert_secp_error(error),
        SigningV2Error::Finalization(error) => assert_finalization_error(error),
        SigningV2Error::WrongState
        | SigningV2Error::RetainedS0Mismatch
        | SigningV2Error::ParseFailed
        | SigningV2Error::ReviewFactsMismatch
        | SigningV2Error::ReviewHashMismatch
        | SigningV2Error::DigestFailed
        | SigningV2Error::InputOutOfRange
        | SigningV2Error::DuplicateTerminalKey
        | SigningV2Error::MissingTerminalKey
        | SigningV2Error::UnexpectedTerminalKey
        | SigningV2Error::TerminalKeyMismatch
        | SigningV2Error::DuplicateSignature
        | SigningV2Error::DuplicateRole
        | SigningV2Error::SignatureConflict
        | SigningV2Error::ThresholdAlreadyMet
        | SigningV2Error::ThresholdWouldBeExceeded
        | SigningV2Error::ThresholdIncomplete
        | SigningV2Error::TooManyInsertions
        | SigningV2Error::TerminalPreInsertionVerificationFailed
        | SigningV2Error::InvalidMockSignature
        | SigningV2Error::ForbiddenDelta
        | SigningV2Error::NonCanonicalOutput
        | SigningV2Error::ArtifactTooLarge
        | SigningV2Error::AllocationFailed
        | SigningV2Error::InternalInvariant => {}
    }
    assert!(!error.to_string().is_empty());
}

fn review_rejected(
    workflow: &mut ReviewReadyV3Workflow,
    stage: Stage,
    error: ReviewReadyV3Error,
    candidate_len: usize,
) -> Outcome {
    assert_review_ready_error(error, candidate_len);
    assert!(workflow.is_finished());
    assert!(workflow.review_ready().is_none());
    assert_eq!(workflow.wake(), Err(ReviewReadyV3Error::Finished));
    Outcome::ReviewRejected { stage, error }
}

fn assert_exact_final(finalized: &FinalizedTransaction) {
    assert_eq!(
        finalized.finalized_psbt(),
        decode_fixture_hex(fixture_value(b"finalized_psbt_hex: "))
    );
    assert_eq!(
        finalized.raw_transaction(),
        decode_fixture_hex(fixture_value(b"raw_transaction_hex: "))
    );
    assert_eq!(
        finalized.txid(),
        decode_fixture_hex_32(fixture_value(b"txid_raw_hex: "))
    );
    assert_eq!(
        finalized.wtxid(),
        decode_fixture_hex_32(fixture_value(b"wtxid_raw_hex: "))
    );
}

fn run_once(
    candidate: &[u8],
    source: InputSource,
    terminal_mode: u8,
    mock_mode: u8,
    hostile_mock: &[u8],
) -> Outcome {
    let mut workflow = match ReviewReadyV3Workflow::new(descriptor()) {
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
    let mocks: Vec<MockCardBSignature<'_>> = owned_mocks
        .iter()
        .map(|mock| MockCardBSignature {
            input_index: mock.input_index,
            der_signature: &mock.der_signature,
        })
        .collect();
    let ready = workflow
        .review_ready()
        .expect("forward path produced schema-v3 ReviewReady");
    assert_eq!(ready.review().schema_version(), REVIEW_V3_SCHEMA_VERSION);
    assert_eq!(
        ready.review().fee_policy_identifier(),
        FEE_POLICY_V2_IDENTIFIER
    );
    let result = workflow.sign_and_finalize_v2(terminal_keys(terminal_mode), &mocks);
    match result {
        Err(error) => {
            assert_signing_error_named(error);
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
            if candidate == golden_s0() && terminal_mode == 0 && mock_mode == 0 {
                assert_exact_final(&finalized);
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

fn assert_signing_error(outcome: &Outcome, expected: SigningV2Error) {
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
            0 => assert!(matches!(outcome, Outcome::Finalized { .. })),
            1 => assert_signing_error(outcome, SigningV2Error::ThresholdIncomplete),
            2 => {}
            3 => assert_signing_error(outcome, SigningV2Error::DuplicateSignature),
            4 => assert_signing_error(outcome, SigningV2Error::DuplicateRole),
            5 => assert_signing_error(outcome, SigningV2Error::InputOutOfRange),
            6 => assert_signing_error(outcome, SigningV2Error::DuplicateSignature),
            _ => unreachable!("mock mode modulo seven is exhaustive"),
        },
        1 => match mock_mode {
            3 => assert_signing_error(outcome, SigningV2Error::DuplicateSignature),
            5 => assert_signing_error(outcome, SigningV2Error::InputOutOfRange),
            _ => assert_signing_error(outcome, SigningV2Error::MissingTerminalKey),
        },
        2 => assert_signing_error(outcome, SigningV2Error::DuplicateTerminalKey),
        3 => assert_signing_error(outcome, SigningV2Error::InputOutOfRange),
        4 => match mock_mode {
            3 => assert_signing_error(outcome, SigningV2Error::DuplicateSignature),
            5 => assert_signing_error(outcome, SigningV2Error::InputOutOfRange),
            _ => assert_signing_error(outcome, SigningV2Error::TerminalKeyMismatch),
        },
        _ => unreachable!("terminal mode modulo five is exhaustive"),
    }
}

fuzz_target!(|data: &[u8]| {
    let (candidate, source, terminal_mode, mock_mode, hostile_mock, expectation) = candidate(data);
    let first = run_once(&candidate, source, terminal_mode, mock_mode, hostile_mock);
    let second = run_once(&candidate, source, terminal_mode, mock_mode, hostile_mock);
    assert_eq!(first, second);
    if expectation == CandidateExpectation::MustReject {
        assert!(matches!(first, Outcome::ReviewRejected { .. }));
    }
    if candidate == golden_s0() {
        assert_exact_control_outcome(&first, terminal_mode, mock_mode);
    }
});
