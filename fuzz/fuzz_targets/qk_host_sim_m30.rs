#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{
    decode_typed_frame, BbqrError, BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES,
    MAX_PART_DECODED_BYTES, MAX_TOTAL_DECODED_BYTES,
};
use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_sim::{
    ExportArtifactKind, ExportArtifacts, FinalizedTransaction, KitTier, ReviewReadyWorkflow,
    SdArtifactMetadata, TierArtifacts,
};
use qk_psbt::InputSource;
use std::sync::OnceLock;

const FIXTURE: &[u8] = include_bytes!("../../host/qk-host-sim/tests/fixtures/m25_export.txt");
const MAX_CONTROL_BYTES: usize = 4_096;
const FRAME_SENTINEL: u8 = 0xa5;
const PART_SENTINEL: u8 = 0x5a;
const PART_LENGTHS: [usize; 10] = [0, 1, 4, 5, 7, 60, 80, 500, 2_680, 4_096];

static GOLDEN_S0: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
enum Outcome {
    UnavailableByTier,
    GeometryRejected(BbqrError),
    Frames {
        frame_bytes: Vec<Vec<u8>>,
        malformed_rejection: BbqrError,
    },
}

fn fixture_value(prefix: &[u8]) -> &'static [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("committed M25 public fixture field")
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
    assert!(encoded.len().is_multiple_of(2));
    let (pairs, remainder) = encoded.as_chunks::<2>();
    assert!(remainder.is_empty());
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

fn fixture_usize(prefix: &[u8]) -> usize {
    core::str::from_utf8(fixture_value(prefix))
        .expect("committed ASCII integer")
        .parse()
        .expect("committed integer field")
}

fn descriptor() -> DescriptorPair {
    parse_descriptor_pair(
        fixture_value(b"receive_descriptor: "),
        fixture_value(b"change_descriptor: "),
    )
    .expect("committed M25 descriptor pair")
}

fn golden_s0() -> &'static [u8] {
    GOLDEN_S0
        .get_or_init(|| decode_fixture_hex(fixture_value(b"initial_psbt_hex: ")))
        .as_slice()
}

fn finalized() -> FinalizedTransaction {
    let mut workflow = ReviewReadyWorkflow::new(descriptor()).expect("M30 fixture workflow");
    let mut caller = golden_s0().to_vec();
    workflow
        .intake(&caller, InputSource::MicroSd)
        .expect("M30 fixture intake");
    caller.fill(0xa5);
    workflow.wake().expect("M30 fixture wake");
    workflow
        .begin_validation()
        .expect("M30 fixture validation start");
    workflow.validate().expect("M30 fixture validation");
    workflow
        .construct_review()
        .expect("M30 fixture review construction");
    let finalized = workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("M30 threshold-complete fixture finalization");
    assert_eq!(
        finalized.raw_transaction(),
        decode_fixture_hex(fixture_value(b"raw_tx_hex: "))
    );
    finalized
}

fn tier(selector: u8) -> KitTier {
    match selector % 3 {
        0 => KitTier::SimpleRecovery,
        1 => KitTier::Inheritance,
        2 => KitTier::QuantumShelter,
        _ => unreachable!("modulo three is exhaustive"),
    }
}

fn assert_metadata(metadata: SdArtifactMetadata, bytes: &[u8]) {
    assert_eq!(metadata.kind(), ExportArtifactKind::RawTransaction);
    assert_eq!(metadata.serialized_len(), fixture_usize(b"raw_tx_len: "));
    assert_eq!(metadata.serialized_len(), bytes.len());
    assert_eq!(
        metadata.sha256(),
        decode_fixture_hex_32(fixture_value(b"raw_tx_sha256: "))
    );
    assert_eq!(
        metadata.txid(),
        decode_fixture_hex_32(fixture_value(b"txid_raw_hex: "))
    );
    assert_eq!(
        metadata.wtxid(),
        decode_fixture_hex_32(fixture_value(b"wtxid_raw_hex: "))
    );
}

fn assert_named_error(error: BbqrError) {
    match error {
        BbqrError::EmptyPayload
        | BbqrError::PayloadTooLarge
        | BbqrError::InvalidNonFinalPartLength
        | BbqrError::TooManyParts
        | BbqrError::PartIndexOutOfRange
        | BbqrError::FrameTooShort
        | BbqrError::FrameTooLarge
        | BbqrError::InvalidMagic
        | BbqrError::UnsupportedEncoding
        | BbqrError::UnsupportedFileType
        | BbqrError::InvalidDeclaredPartCount
        | BbqrError::DeclaredPartCountExceeded
        | BbqrError::InvalidPartIndex
        | BbqrError::EmptyPart
        | BbqrError::Base32PaddingForbidden
        | BbqrError::MalformedBase32Symbol
        | BbqrError::NonCanonicalBase32Length
        | BbqrError::NonCanonicalBase32Padding
        | BbqrError::NonFinalPartLengthNotMultipleOfFive
        | BbqrError::StreamEncodingMismatch
        | BbqrError::StreamFileTypeMismatch
        | BbqrError::StreamPartCountMismatch
        | BbqrError::NonUniformPartLength
        | BbqrError::FinalPartTooLarge
        | BbqrError::TotalDecodedSizeExceeded
        | BbqrError::ConflictingDuplicate
        | BbqrError::DuplicateWorkExceeded
        | BbqrError::SubmissionWorkExceeded
        | BbqrError::Incomplete
        | BbqrError::AlreadyComplete => {}
    }
    assert!(!error.to_string().is_empty());
}

fn malformed_frame(frame: &[u8], selector: u8) -> (Vec<u8>, BbqrError) {
    let mut candidate = frame.to_vec();
    let expected = match selector % 7 {
        0 => {
            candidate[2] = b'H';
            BbqrError::UnsupportedEncoding
        }
        1 => {
            candidate[3] = b'P';
            BbqrError::UnsupportedFileType
        }
        2 => {
            candidate[4..6].copy_from_slice(b"00");
            BbqrError::InvalidDeclaredPartCount
        }
        3 => {
            candidate[6..8].copy_from_slice(b"ZZ");
            BbqrError::InvalidPartIndex
        }
        4 => {
            candidate[8] = b'=';
            BbqrError::Base32PaddingForbidden
        }
        5 => {
            candidate[8] = b'0';
            BbqrError::MalformedBase32Symbol
        }
        6 => {
            while matches!((candidate.len() - 8) % 8, 0 | 2 | 4 | 5 | 7) {
                candidate.pop().expect("emitted frame has a body");
            }
            BbqrError::NonCanonicalBase32Length
        }
        _ => unreachable!("modulo seven is exhaustive"),
    };
    (candidate, expected)
}

fn exercise_malformed(frame: &[u8], selector: u8) -> BbqrError {
    let (candidate, expected) = malformed_frame(frame, selector);
    let mut output = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    let error = decode_typed_frame(BbqrFileType::Transaction, &candidate, &mut output)
        .expect_err("the selected malformed frame must reject");
    assert_named_error(error);
    assert_eq!(error, expected);
    assert_eq!(output, [PART_SENTINEL; MAX_PART_DECODED_BYTES]);
    error
}

fn run_once(data: &[u8]) -> Outcome {
    let selected_tier = tier(data.first().copied().unwrap_or(0));
    let part_selector = data.get(1).copied().unwrap_or(5);
    let part_len = PART_LENGTHS[usize::from(part_selector) % PART_LENGTHS.len()];
    let mutation_selector = data.get(2).copied().unwrap_or(0);
    let raw_bytes = decode_fixture_hex(fixture_value(b"raw_tx_hex: "));

    let owner = ExportArtifacts::from_finalized(finalized(), selected_tier)
        .expect("M30 finalized capability must bind");
    assert_eq!(owner.tier(), selected_tier);
    let raw_from_tier = match owner.artifacts() {
        TierArtifacts::SimpleRecovery {
            raw_transaction, ..
        }
        | TierArtifacts::Inheritance {
            raw_transaction, ..
        }
        | TierArtifacts::QuantumShelter { raw_transaction } => raw_transaction,
    };
    assert_eq!(raw_from_tier.bytes(), raw_bytes);
    assert_metadata(raw_from_tier.metadata(), raw_from_tier.bytes());

    let capability = owner.quantum_shelter_qr();
    if selected_tier != KitTier::QuantumShelter {
        assert!(capability.is_none());
        return Outcome::UnavailableByTier;
    }
    let artifact = capability.expect("Quantum Shelter owns type-T framing");
    assert_eq!(artifact.bytes(), raw_bytes);
    assert_metadata(artifact.metadata(), artifact.bytes());

    let mut encoder = match artifact.bbqr(part_len) {
        Ok(encoder) => encoder,
        Err(error) => {
            assert_named_error(error);
            return Outcome::GeometryRejected(error);
        }
    };
    let declared_parts = encoder.declared_parts();
    let mut frame_buffer = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
    let mut frames = Vec::with_capacity(usize::from(declared_parts));
    loop {
        frame_buffer.fill(FRAME_SENTINEL);
        let Some(facts) = encoder
            .next_frame(&mut frame_buffer)
            .expect("accepted geometry must emit every frame")
        else {
            break;
        };
        assert_eq!(facts.declared_parts(), declared_parts);
        assert_eq!(usize::from(facts.part_index()), frames.len());
        assert_eq!(&frame_buffer[..4], b"B$2T");
        assert!(frame_buffer[facts.frame_len()..]
            .iter()
            .all(|byte| *byte == FRAME_SENTINEL));
        frames.push(frame_buffer[..facts.frame_len()].to_vec());
    }
    assert_eq!(frames.len(), usize::from(declared_parts));
    frame_buffer.fill(PART_SENTINEL);
    assert_eq!(encoder.next_frame(&mut frame_buffer), Ok(None));
    assert_eq!(frame_buffer, [PART_SENTINEL; MAX_FRAME_TEXT_BYTES]);

    let malformed_rejection = exercise_malformed(&frames[0], mutation_selector);
    let mut storage = [0u8; MAX_TOTAL_DECODED_BYTES];
    let mut reassembler = Reassembler::new_typed(BbqrFileType::Transaction, &mut storage);
    for (index, frame) in frames.iter().enumerate() {
        let progress = reassembler
            .submit(frame)
            .expect("sequential emitted frames must reassemble");
        assert_eq!(progress.declared_parts, declared_parts);
        assert_eq!(usize::from(progress.received_parts), index + 1);
    }
    assert_eq!(reassembler.payload().expect("complete stream"), raw_bytes);

    Outcome::Frames {
        frame_bytes: frames,
        malformed_rejection,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CONTROL_BYTES {
        return;
    }
    let first = run_once(data);
    let repeated = run_once(data);
    assert_eq!(first, repeated);
});
