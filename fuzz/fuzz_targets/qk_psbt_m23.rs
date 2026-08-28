#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_psbt::{
    build_review_v3, DirectRbf, InputSource, IntakeError, OwnedS0, RejectCategory, ReviewContext,
    ReviewNetwork, ReviewV3, ReviewV3Error, FEE_POLICY_V2_IDENTIFIER,
    MAX_CANONICAL_REVIEW_V3_BYTES, MAX_ESTIMATED_VSIZE_V2, MAX_FEE_WARNINGS_V2,
    REVIEW_V3_HASH_DOMAIN, REVIEW_V3_SCHEMA_VERSION,
};
use std::sync::OnceLock;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_MUTATIONS: usize = 64;
const DESCRIPTOR_FIXTURE: &[u8] =
    include_bytes!("../../host/qk-descriptor/tests/fixtures/descriptor_pairs.txt");
const REVIEW_FIXTURE: &[u8] = include_bytes!("../../host/qk-psbt/tests/fixtures/review_v3.txt");

static DESCRIPTOR: OnceLock<DescriptorPairV2> = OnceLock::new();
static GOLDEN_S0: OnceLock<Vec<u8>> = OnceLock::new();

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

fn descriptor() -> &'static DescriptorPairV2 {
    DESCRIPTOR.get_or_init(|| {
        let receive = fixture_value(DESCRIPTOR_FIXTURE, b"receive: ");
        let change = fixture_value(DESCRIPTOR_FIXTURE, b"change: ");
        parse_descriptor_pair_v2(receive, change).expect("committed public v2 descriptor pair")
    })
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

fn candidate(data: &[u8]) -> (Vec<u8>, InputSource) {
    let selector = data.first().copied().unwrap_or(0);
    let remainder = data.get(1..).unwrap_or_default();
    let bytes = match selector % 4 {
        0 => remainder
            .get(..remainder.len().min(MAX_CANDIDATE_BYTES))
            .unwrap_or_default()
            .to_vec(),
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
        _ => unreachable!("modulo four is exhaustive"),
    };
    (bytes, source(selector))
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

fn intake_error_name(error: IntakeError) -> &'static str {
    match error {
        IntakeError::TooLarge => "TooLarge",
        IntakeError::AllocationFailed => "AllocationFailed",
        IntakeError::HashFailure => "HashFailure",
    }
}

fn review_error_name(error: ReviewV3Error) -> &'static str {
    match error {
        ReviewV3Error::SourceMismatch => "SourceMismatch",
        ReviewV3Error::Semantic(semantic) => {
            assert!(!semantic.category.to_string().is_empty());
            "Semantic"
        }
        ReviewV3Error::FeePolicyArithmeticOverflow => "FeePolicyArithmeticOverflow",
        ReviewV3Error::EmergencyFeeCeilingExceeded => "EmergencyFeeCeilingExceeded",
        ReviewV3Error::InputCountTooLarge => "InputCountTooLarge",
        ReviewV3Error::OutputCountTooLarge => "OutputCountTooLarge",
        ReviewV3Error::UnsignedTransactionTooLong => "UnsignedTransactionTooLong",
        ReviewV3Error::InputIndexMismatch => "InputIndexMismatch",
        ReviewV3Error::OutputIndexMismatch => "OutputIndexMismatch",
        ReviewV3Error::LengthOverflow => "LengthOverflow",
        ReviewV3Error::FieldLengthOverflow => "FieldLengthOverflow",
        ReviewV3Error::CanonicalTooLong => "CanonicalTooLong",
        ReviewV3Error::AllocationFailed => "AllocationFailed",
        ReviewV3Error::HashFailure => "HashFailure",
        ReviewV3Error::UnsupportedReviewSchemaVersion => "UnsupportedReviewSchemaVersion",
        ReviewV3Error::CanonicalReviewMismatch => "CanonicalReviewMismatch",
        ReviewV3Error::InternalInvariant => "InternalInvariant",
    }
}

fn opposite_source(source: InputSource) -> InputSource {
    match source {
        InputSource::MicroSd => InputSource::Qr,
        InputSource::Qr => InputSource::MicroSd,
    }
}

fn context(source: InputSource) -> ReviewContext {
    ReviewContext {
        network: ReviewNetwork::BitcoinMainnet,
        input_source: source,
    }
}

fn assert_review(review: &ReviewV3, owned: &OwnedS0, source: InputSource) {
    assert_eq!(REVIEW_V3_SCHEMA_VERSION, 3);
    assert_eq!(FEE_POLICY_V2_IDENTIFIER, b"QK-FEE-POLICY-V2");
    assert_eq!(REVIEW_V3_HASH_DOMAIN, b"QuietKey/D-09/review/v3");
    assert_eq!(review.schema_version(), REVIEW_V3_SCHEMA_VERSION);
    assert_eq!(review.context(), context(source));
    assert_eq!(review.s0_sha256(), owned.sha256());
    assert_eq!(review.wallet_id(), descriptor().wallet_id());
    assert_eq!(
        review.origin_fingerprints(),
        descriptor().origin_fingerprints()
    );
    assert_eq!(review.fee_policy_identifier(), FEE_POLICY_V2_IDENTIFIER);
    assert!(review.canonical_bytes().len() <= MAX_CANONICAL_REVIEW_V3_BYTES);
    assert_eq!(
        review.canonical_bytes().first().copied(),
        Some(REVIEW_V3_SCHEMA_VERSION)
    );
    assert!(review.estimated_vsize() <= MAX_ESTIMATED_VSIZE_V2);
    assert!(review.fee() <= 5_000_000);
    assert_eq!(
        review
            .total_input_amount()
            .checked_sub(review.total_output_amount()),
        Some(review.fee())
    );
    assert_eq!(review.review_hash(), review.review_hash());
    assert_eq!(&review.clone(), review);

    let warning_tags: Vec<u8> = review.fee_warnings().map(|warning| warning.tag()).collect();
    assert!(warning_tags.len() <= MAX_FEE_WARNINGS_V2);
    assert!(warning_tags.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(warning_tags.len(), review.fee_policy().warning_count());

    for input in review.inputs() {
        assert_eq!(input.effective_sighash(), 1);
        let expected = if input.sequence() < 0xffff_fffe {
            DirectRbf::Signaled
        } else {
            DirectRbf::NotSignaled
        };
        assert_eq!(input.direct_rbf(), expected);
    }
    let aggregate = if review
        .inputs()
        .iter()
        .any(|input| input.sequence() < 0xffff_fffe)
    {
        DirectRbf::Signaled
    } else {
        DirectRbf::NotSignaled
    };
    assert_eq!(review.direct_rbf(), aggregate);

    let canonical_before = review.canonical_bytes().to_vec();
    let hash_before = review.review_hash();
    assert_eq!(review.verify_exact_identity(&canonical_before), Ok(()));

    assert_eq!(
        review.verify_exact_identity(&[]),
        Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
    );
    for legacy_schema in [1, 2] {
        let mut presented = canonical_before.clone();
        presented[0] = legacy_schema;
        assert_eq!(
            review.verify_exact_identity(&presented),
            Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
        );
    }

    let mut mismatched_v3 = canonical_before.clone();
    let last = mismatched_v3
        .last_mut()
        .expect("accepted canonical review is non-empty");
    *last ^= 1;
    assert_eq!(
        review.verify_exact_identity(&mismatched_v3),
        Err(ReviewV3Error::CanonicalReviewMismatch)
    );

    assert_eq!(review.canonical_bytes(), canonical_before);
    assert_eq!(review.review_hash(), hash_before);
}

fn exercise(candidate: &[u8], source: InputSource) {
    let owned = match OwnedS0::new(candidate, source) {
        Ok(owned) => owned,
        Err(error) => {
            assert!(!intake_error_name(error).is_empty());
            assert_eq!(OwnedS0::new(candidate, source).unwrap_err(), error);
            return;
        }
    };
    assert_eq!(owned.bytes(), candidate);
    assert_eq!(owned.source(), source);

    let view = match owned.parse() {
        Ok(view) => view,
        Err(error) => {
            assert!(error.offset <= candidate.len());
            assert!(!reject_name(error.category).is_empty());
            assert_eq!(owned.parse().unwrap_err(), error);
            return;
        }
    };
    assert_eq!(view.buffer(), owned.bytes());
    assert_eq!(view.source(), source);

    assert_eq!(
        build_review_v3(&view, descriptor(), context(opposite_source(source))),
        Err(ReviewV3Error::SourceMismatch)
    );

    let first = build_review_v3(&view, descriptor(), context(source));
    let reparsed = owned
        .parse()
        .expect("accepted retained S0 must deterministically reparse");
    let second = build_review_v3(&reparsed, descriptor(), context(source));
    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(first, second);
            assert_review(&first, &owned, source);
        }
        (Err(first), Err(second)) => {
            assert_eq!(first, second);
            assert!(!review_error_name(first).is_empty());
        }
        _ => panic!("slice-2 review construction changed result on exact retained reparse"),
    }
}

fuzz_target!(|data: &[u8]| {
    let (candidate, source) = candidate(data);
    exercise(&candidate, source);
});
