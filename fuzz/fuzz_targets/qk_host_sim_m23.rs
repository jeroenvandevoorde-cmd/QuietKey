#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_host_sim::{ReviewReadyV3Error, ReviewReadyV3Workflow, WorkflowRejection};
use qk_psbt::{
    InputSource, IntakeError, OwnedS0, ParseError, RejectCategory, ReviewV3Error,
    FEE_POLICY_V2_IDENTIFIER, MAX_CANONICAL_REVIEW_V3_BYTES, REVIEW_V3_SCHEMA_VERSION,
};
use std::sync::OnceLock;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_MUTATIONS: usize = 64;
const DESCRIPTOR_FIXTURE: &[u8] =
    include_bytes!("../../host/qk-descriptor/tests/fixtures/descriptor_pairs.txt");
const REVIEW_FIXTURE: &[u8] = include_bytes!("../../host/qk-psbt/tests/fixtures/review_v3.txt");
const GOLDEN_WALLET_ID: [u8; 32] = [
    0xd5, 0xb7, 0xe5, 0x2f, 0x56, 0x9a, 0xe5, 0x1e, 0x7c, 0x66, 0xaf, 0x14, 0x24, 0x0d, 0x8e, 0x44,
    0x59, 0xc6, 0x24, 0x67, 0x85, 0xce, 0x5c, 0x44, 0x17, 0x73, 0x99, 0x56, 0x14, 0xf6, 0x0e, 0x9e,
];
const GOLDEN_FINGERPRINTS: [[u8; 4]; 2] = [[0x2f, 0xae, 0x97, 0x11], [0x72, 0xa1, 0x4a, 0xb8]];

static GOLDEN_S0: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    New,
    Intake,
    Wake,
    BeginValidation,
    Validate,
    ConstructReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateExpectation {
    MustReject,
    ExactGolden,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Rejected {
        stage: Stage,
        error: ReviewReadyV3Error,
    },
    Ready {
        review_hash: [u8; 32],
        s0_sha256: [u8; 32],
        s0_len: usize,
        source: InputSource,
        canonical: Vec<u8>,
    },
}

fn fixture_value<'a>(fixture: &'a [u8], prefix: &[u8]) -> &'a [u8] {
    fixture
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("committed public fixture field")
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
    encoded
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).expect("committed fixture high hex digit");
            let low = hex_nibble(pair[1]).expect("committed fixture low hex digit");
            (high << 4) | low
        })
        .collect()
}

fn descriptor() -> DescriptorPairV2 {
    let receive = fixture_value(DESCRIPTOR_FIXTURE, b"receive: ");
    let change = fixture_value(DESCRIPTOR_FIXTURE, b"change: ");
    parse_descriptor_pair_v2(receive, change).expect("committed public v2 descriptor pair")
}

fn golden_s0() -> &'static [u8] {
    GOLDEN_S0
        .get_or_init(|| decode_fixture_hex(fixture_value(REVIEW_FIXTURE, b"s0_hex: ")))
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
    for command in commands.chunks_exact(4).take(MAX_MUTATIONS) {
        let [operation, high, low, value] = command else {
            unreachable!("chunks_exact(4) always yields four bytes")
        };
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

fn candidate(data: &[u8]) -> (Vec<u8>, InputSource, u8, CandidateExpectation) {
    let selector = data.first().copied().unwrap_or(0);
    let remainder = data.get(1..).unwrap_or_default();
    let (bytes, expectation) = match selector % 4 {
        0 => {
            let bytes = remainder
                .get(..remainder.len().min(MAX_CANDIDATE_BYTES))
                .unwrap_or_default()
                .to_vec();
            let expectation = if bytes.is_empty() {
                CandidateExpectation::MustReject
            } else if bytes == golden_s0() {
                CandidateExpectation::ExactGolden
            } else {
                CandidateExpectation::Unknown
            };
            (bytes, expectation)
        }
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
        _ => unreachable!("modulo four is exhaustive"),
    };
    (bytes, source(selector), (selector >> 3) % 4, expectation)
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

fn assert_named_error(error: ReviewReadyV3Error, candidate_len: usize) {
    match error {
        ReviewReadyV3Error::Intake(error) => {
            assert!(!intake_error_name(error).is_empty());
        }
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

fn rejected(
    workflow: &mut ReviewReadyV3Workflow,
    stage: Stage,
    error: ReviewReadyV3Error,
    candidate_len: usize,
) -> Outcome {
    assert_named_error(error, candidate_len);
    assert!(workflow.is_finished());
    assert!(workflow.review_ready().is_none());
    assert_eq!(workflow.wake(), Err(ReviewReadyV3Error::Finished));
    Outcome::Rejected { stage, error }
}

fn run_once(candidate: &[u8], source: InputSource, sequence: u8) -> Outcome {
    let mut caller = candidate.to_vec();
    let mut workflow = match ReviewReadyV3Workflow::new(descriptor()) {
        Ok(workflow) => workflow,
        Err(error) => {
            assert_named_error(error, candidate.len());
            return Outcome::Rejected {
                stage: Stage::New,
                error,
            };
        }
    };
    assert!(workflow.review_ready().is_none());
    assert!(!workflow.is_finished());

    match sequence {
        0 => {
            if let Err(error) = workflow.intake(&caller, source) {
                return rejected(&mut workflow, Stage::Intake, error, candidate.len());
            }
            caller.fill(0xa5);
            if let Err(error) = workflow.wake() {
                return rejected(&mut workflow, Stage::Wake, error, candidate.len());
            }
            if let Err(error) = workflow.begin_validation() {
                return rejected(
                    &mut workflow,
                    Stage::BeginValidation,
                    error,
                    candidate.len(),
                );
            }
            if let Err(error) = workflow.validate() {
                return rejected(&mut workflow, Stage::Validate, error, candidate.len());
            }
            if let Err(error) = workflow.construct_review() {
                return rejected(
                    &mut workflow,
                    Stage::ConstructReview,
                    error,
                    candidate.len(),
                );
            }
        }
        1 => {
            let error = workflow
                .begin_validation()
                .expect_err("out-of-order begin-validation must reject");
            return rejected(
                &mut workflow,
                Stage::BeginValidation,
                error,
                candidate.len(),
            );
        }
        2 => {
            if let Err(error) = workflow.intake(&caller, source) {
                return rejected(&mut workflow, Stage::Intake, error, candidate.len());
            }
            caller.fill(0xa5);
            if let Err(error) = workflow.wake() {
                return rejected(&mut workflow, Stage::Wake, error, candidate.len());
            }
            let error = workflow
                .validate()
                .expect_err("out-of-order validation must reject");
            return rejected(&mut workflow, Stage::Validate, error, candidate.len());
        }
        3 => {
            if let Err(error) = workflow.intake(&caller, source) {
                return rejected(&mut workflow, Stage::Intake, error, candidate.len());
            }
            caller.fill(0xa5);
            if let Err(error) = workflow.wake() {
                return rejected(&mut workflow, Stage::Wake, error, candidate.len());
            }
            if let Err(error) = workflow.begin_validation() {
                return rejected(
                    &mut workflow,
                    Stage::BeginValidation,
                    error,
                    candidate.len(),
                );
            }
            let error = workflow
                .construct_review()
                .expect_err("out-of-order review construction must reject");
            return rejected(
                &mut workflow,
                Stage::ConstructReview,
                error,
                candidate.len(),
            );
        }
        _ => unreachable!("modulo four is exhaustive"),
    }

    assert!(!workflow.is_finished());
    let ready = workflow
        .review_ready()
        .expect("forward path produced ReviewReady");
    assert_eq!(ready.s0_len(), candidate.len());
    assert_eq!(ready.input_source(), source);
    assert_eq!(ready.s0_sha256(), ready.review().s0_sha256());
    assert_eq!(ready.review_hash(), ready.review().review_hash().unwrap());
    assert_eq!(ready.review().schema_version(), REVIEW_V3_SCHEMA_VERSION);
    assert_eq!(
        ready.review().fee_policy_identifier(),
        FEE_POLICY_V2_IDENTIFIER
    );
    assert_eq!(ready.review().wallet_id(), GOLDEN_WALLET_ID);
    assert_eq!(ready.review().origin_fingerprints(), GOLDEN_FINGERPRINTS);
    assert_eq!(
        ready.s0_sha256(),
        OwnedS0::new(candidate, source)
            .expect("accepted workflow candidate remains within source cap")
            .sha256()
    );
    assert!(ready.review().canonical_bytes().len() <= MAX_CANONICAL_REVIEW_V3_BYTES);

    let mut wrong_schema = ready.review().canonical_bytes().to_vec();
    assert!(!wrong_schema.is_empty());
    for old_schema in [1, 2] {
        wrong_schema[0] = old_schema;
        assert_eq!(
            ready.review().verify_exact_identity(&wrong_schema),
            Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
        );
    }
    wrong_schema[0] = REVIEW_V3_SCHEMA_VERSION;
    wrong_schema.push(0);
    assert_eq!(
        ready.review().verify_exact_identity(&wrong_schema),
        Err(ReviewV3Error::CanonicalReviewMismatch)
    );
    assert_eq!(
        ready
            .review()
            .verify_exact_identity(ready.review().canonical_bytes()),
        Ok(())
    );
    if candidate == golden_s0() && source == InputSource::MicroSd {
        let expected_canonical =
            decode_fixture_hex(fixture_value(REVIEW_FIXTURE, b"canonical_review_v3_hex: "));
        let expected_hash = decode_fixture_hex(fixture_value(REVIEW_FIXTURE, b"review_hash: "));
        assert_eq!(ready.review().canonical_bytes(), expected_canonical);
        assert_eq!(ready.review_hash().as_slice(), expected_hash);
        assert_eq!(
            ready.s0_sha256().as_slice(),
            decode_fixture_hex(fixture_value(REVIEW_FIXTURE, b"s0_sha256: "))
        );
    }

    Outcome::Ready {
        review_hash: ready.review_hash(),
        s0_sha256: ready.s0_sha256(),
        s0_len: ready.s0_len(),
        source: ready.input_source(),
        canonical: ready.review().canonical_bytes().to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    let (candidate, source, sequence, expectation) = candidate(data);
    let first = run_once(&candidate, source, sequence);
    let second = run_once(&candidate, source, sequence);
    assert_eq!(first, second);
    if sequence == 0 {
        match expectation {
            CandidateExpectation::MustReject => {
                assert!(matches!(first, Outcome::Rejected { .. }));
            }
            CandidateExpectation::ExactGolden => {
                assert!(matches!(first, Outcome::Ready { .. }));
            }
            CandidateExpectation::Unknown => {}
        }
    }
});
