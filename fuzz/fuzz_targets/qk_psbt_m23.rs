#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_psbt::{
    build_review_v2, DirectRbf, InputSource, IntakeError, OwnedS0, RejectCategory, ReviewContext,
    ReviewNetwork, ReviewV2, ReviewV2Error, FEE_POLICY_IDENTIFIER, MAX_CANONICAL_REVIEW_V2_BYTES,
    MAX_ESTIMATED_VSIZE, MAX_FEE_WARNINGS, REVIEW_V2_SCHEMA_VERSION,
};
use std::sync::OnceLock;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_MUTATIONS: usize = 64;
const DESCRIPTOR_FIXTURE: &[u8] =
    include_bytes!("../../host/qk-psbt/tests/fixtures/descriptor_ownership.txt");
const REVIEW_FIXTURE: &[u8] = include_bytes!("../../host/qk-psbt/tests/fixtures/review_v2.txt");

static DESCRIPTOR: OnceLock<DescriptorPair> = OnceLock::new();
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

fn descriptor() -> &'static DescriptorPair {
    DESCRIPTOR.get_or_init(|| {
        let receive = fixture_value(DESCRIPTOR_FIXTURE, b"receive: ");
        let change = fixture_value(DESCRIPTOR_FIXTURE, b"change: ");
        parse_descriptor_pair(receive, change).expect("committed public descriptor pair")
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

fn review_error_name(error: ReviewV2Error) -> &'static str {
    match error {
        ReviewV2Error::SourceMismatch => "SourceMismatch",
        ReviewV2Error::Semantic(semantic) => {
            assert!(!semantic.category.to_string().is_empty());
            "Semantic"
        }
        ReviewV2Error::FeePolicyArithmeticOverflow => "FeePolicyArithmeticOverflow",
        ReviewV2Error::EmergencyFeeCeilingExceeded => "EmergencyFeeCeilingExceeded",
        ReviewV2Error::InputCountTooLarge => "InputCountTooLarge",
        ReviewV2Error::OutputCountTooLarge => "OutputCountTooLarge",
        ReviewV2Error::UnsignedTransactionTooLong => "UnsignedTransactionTooLong",
        ReviewV2Error::InputIndexMismatch => "InputIndexMismatch",
        ReviewV2Error::OutputIndexMismatch => "OutputIndexMismatch",
        ReviewV2Error::LengthOverflow => "LengthOverflow",
        ReviewV2Error::FieldLengthOverflow => "FieldLengthOverflow",
        ReviewV2Error::CanonicalTooLong => "CanonicalTooLong",
        ReviewV2Error::AllocationFailed => "AllocationFailed",
        ReviewV2Error::HashFailure => "HashFailure",
        ReviewV2Error::InternalInvariant => "InternalInvariant",
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

fn assert_review(review: &ReviewV2, owned: &OwnedS0, source: InputSource) {
    assert_eq!(review.schema_version(), REVIEW_V2_SCHEMA_VERSION);
    assert_eq!(review.context(), context(source));
    assert_eq!(review.s0_sha256(), owned.sha256());
    assert_eq!(review.wallet_id(), descriptor().wallet_id());
    assert_eq!(review.fee_policy_identifier(), FEE_POLICY_IDENTIFIER);
    assert!(review.canonical_bytes().len() <= MAX_CANONICAL_REVIEW_V2_BYTES);
    assert!(review.estimated_vsize() <= MAX_ESTIMATED_VSIZE);
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
    assert!(warning_tags.len() <= MAX_FEE_WARNINGS);
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
        build_review_v2(&view, descriptor(), context(opposite_source(source))),
        Err(ReviewV2Error::SourceMismatch)
    );

    let first = build_review_v2(&view, descriptor(), context(source));
    let reparsed = owned
        .parse()
        .expect("accepted retained S0 must deterministically reparse");
    let second = build_review_v2(&reparsed, descriptor(), context(source));
    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert_eq!(first, second);
            assert_review(&first, &owned, source);
        }
        (Err(first), Err(second)) => {
            assert_eq!(first, second);
            assert!(!review_error_name(first).is_empty());
        }
        _ => panic!("M23 review construction changed result on exact retained reparse"),
    }
}

fuzz_target!(|data: &[u8]| {
    let (candidate, source) = candidate(data);
    exercise(&candidate, source);
});
