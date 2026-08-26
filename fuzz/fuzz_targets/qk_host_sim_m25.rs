#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{BbqrError, Reassembler, MAX_FRAME_TEXT_BYTES, MAX_TOTAL_DECODED_BYTES};
use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_sim::{
    ExportArtifactKind, ExportArtifacts, ExportNonce, FinalizedPsbtArtifact, FinalizedTransaction,
    KitTier, MockSdFilesystem, RawTransactionArtifact, ReviewReadyWorkflow, SdArtifactMetadata,
    SdExportError, SdExportFault, SdLifecycleEvent, SdPublishedArtifact, TierArtifacts,
};
use qk_psbt::InputSource;
use std::sync::OnceLock;

const MAX_CONTROL_BYTES: usize = 4_096;
const FIXTURE: &[u8] = include_bytes!("../../host/qk-host-sim/tests/fixtures/m25_export.txt");
const PART_LENGTHS: [usize; 10] = [0, 1, 4, 5, 7, 60, 80, 500, 2_680, 4_096];
const INPUT_NAME: &str = "immutable-input.psbt";
const COLLISION_BYTES: &[u8] = b"pre-existing destination";

static GOLDEN_S0: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Clone, Copy)]
enum SelectedArtifact<'a> {
    FinalizedPsbt(FinalizedPsbtArtifact<'a>),
    RawTransaction(RawTransactionArtifact<'a>),
}

impl SelectedArtifact<'_> {
    fn kind(self) -> ExportArtifactKind {
        match self {
            Self::FinalizedPsbt(_) => ExportArtifactKind::FinalizedPsbt,
            Self::RawTransaction(_) => ExportArtifactKind::RawTransaction,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BbqrOutcome {
    NotApplicable,
    Rejected(BbqrError),
    Frames(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PublicationOutcome {
    UnavailableByTier,
    Attempted(Box<PublicationAttempt>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicationAttempt {
    result: Result<SdPublishedArtifact, SdExportError>,
    events: Vec<SdLifecycleEvent>,
    final_bytes: Option<Vec<u8>>,
    temporary_bytes: Option<Vec<u8>>,
    input_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Outcome {
    tier: KitTier,
    selected_kind: ExportArtifactKind,
    bbqr: BbqrOutcome,
    publication: PublicationOutcome,
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
    assert!(
        encoded.len().is_multiple_of(2),
        "committed fixture hex width"
    );
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
    let mut workflow = ReviewReadyWorkflow::new(descriptor()).expect("M25 fixture workflow");
    let mut caller = golden_s0().to_vec();
    workflow
        .intake(&caller, InputSource::MicroSd)
        .expect("M25 fixture intake");
    caller.fill(0xa5);
    workflow.wake().expect("M25 fixture wake");
    workflow
        .begin_validation()
        .expect("M25 fixture validation start");
    workflow.validate().expect("M25 fixture validation");
    workflow
        .construct_review()
        .expect("M25 fixture review construction");
    let finalized = workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("M25 threshold-complete fixture finalization");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_fixture_hex(fixture_value(b"finalized_psbt_hex: "))
    );
    assert_eq!(
        finalized.raw_transaction(),
        decode_fixture_hex(fixture_value(b"raw_tx_hex: "))
    );
    assert_eq!(
        finalized.txid(),
        decode_fixture_hex_32(fixture_value(b"txid_raw_hex: "))
    );
    assert_eq!(
        finalized.wtxid(),
        decode_fixture_hex_32(fixture_value(b"wtxid_raw_hex: "))
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

fn selected_kind(selector: u8) -> ExportArtifactKind {
    if selector & 1 == 0 {
        ExportArtifactKind::FinalizedPsbt
    } else {
        ExportArtifactKind::RawTransaction
    }
}

fn select_artifact<'a>(
    artifacts: TierArtifacts<'a>,
    kind: ExportArtifactKind,
) -> Option<SelectedArtifact<'a>> {
    match (artifacts, kind) {
        (
            TierArtifacts::SimpleRecovery { finalized_psbt, .. }
            | TierArtifacts::Inheritance { finalized_psbt, .. },
            ExportArtifactKind::FinalizedPsbt,
        ) => Some(SelectedArtifact::FinalizedPsbt(finalized_psbt)),
        (
            TierArtifacts::SimpleRecovery {
                raw_transaction, ..
            }
            | TierArtifacts::Inheritance {
                raw_transaction, ..
            }
            | TierArtifacts::QuantumShelter { raw_transaction },
            ExportArtifactKind::RawTransaction,
        ) => Some(SelectedArtifact::RawTransaction(raw_transaction)),
        (TierArtifacts::QuantumShelter { .. }, ExportArtifactKind::FinalizedPsbt) => None,
    }
}

fn artifact_bytes<'a>(artifact: SelectedArtifact<'a>) -> &'a [u8] {
    match artifact {
        SelectedArtifact::FinalizedPsbt(value) => value.bytes(),
        SelectedArtifact::RawTransaction(value) => value.bytes(),
    }
}

fn artifact_metadata(artifact: SelectedArtifact<'_>) -> SdArtifactMetadata {
    match artifact {
        SelectedArtifact::FinalizedPsbt(value) => value.metadata(),
        SelectedArtifact::RawTransaction(value) => value.metadata(),
    }
}

fn write_artifact(
    artifact: SelectedArtifact<'_>,
    nonce: ExportNonce,
    filesystem: &mut MockSdFilesystem,
    fault: Option<SdExportFault>,
) -> Result<SdPublishedArtifact, SdExportError> {
    match artifact {
        SelectedArtifact::FinalizedPsbt(value) => value.write_mock_sd(nonce, filesystem, fault),
        SelectedArtifact::RawTransaction(value) => value.write_mock_sd(nonce, filesystem, fault),
    }
}

fn assert_metadata(kind: ExportArtifactKind, metadata: SdArtifactMetadata) {
    let (len_prefix, hash_prefix) = match kind {
        ExportArtifactKind::FinalizedPsbt => (
            b"finalized_psbt_len: ".as_slice(),
            b"finalized_psbt_sha256: ".as_slice(),
        ),
        ExportArtifactKind::RawTransaction => {
            (b"raw_tx_len: ".as_slice(), b"raw_tx_sha256: ".as_slice())
        }
    };
    assert_eq!(metadata.kind(), kind);
    assert_eq!(metadata.serialized_len(), fixture_usize(len_prefix));
    assert_eq!(
        metadata.sha256(),
        decode_fixture_hex_32(fixture_value(hash_prefix))
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

fn nonce(control: &[u8]) -> ([u8; 16], ExportNonce) {
    let mut bytes: [u8; 16] = decode_fixture_hex(fixture_value(b"export_nonce_hex: "))
        .try_into()
        .expect("committed 128-bit nonce");
    for (destination, source) in bytes.iter_mut().zip(control.iter().copied()) {
        *destination = source;
    }
    (bytes, ExportNonce::from_bytes(bytes))
}

fn artifact_name(kind: ExportArtifactKind, nonce: [u8; 16], temporary: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let suffix = match kind {
        ExportArtifactKind::FinalizedPsbt => "-final.psbt",
        ExportArtifactKind::RawTransaction => "-final.tx",
    };
    let mut name = String::with_capacity(3 + 32 + suffix.len() + usize::from(temporary) * 4);
    name.push_str("qk-");
    for byte in nonce {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(suffix);
    if temporary {
        name.push_str(".tmp");
    }
    name
}

fn fault(control: u8) -> (Option<SdExportFault>, Option<SdExportError>, bool) {
    match control % 10 {
        0 => (None, None, false),
        1 => (
            Some(SdExportFault::FullMedia),
            Some(SdExportError::FullMedia),
            false,
        ),
        2 => (
            Some(SdExportFault::TemporaryCreateFailed),
            Some(SdExportError::TemporaryCreateFailed),
            false,
        ),
        3 => (
            Some(SdExportFault::WriteFailed),
            Some(SdExportError::WriteFailed),
            false,
        ),
        4 => (
            Some(SdExportFault::SyncFailed),
            Some(SdExportError::SyncFailed),
            false,
        ),
        5 => (
            Some(SdExportFault::CloseFailed),
            Some(SdExportError::CloseFailed),
            false,
        ),
        6 => (
            Some(SdExportFault::ReopenFailed),
            Some(SdExportError::ReopenFailed),
            false,
        ),
        7 => (
            Some(SdExportFault::VerificationMismatch),
            Some(SdExportError::VerificationMismatch),
            false,
        ),
        8 => (
            Some(SdExportFault::RenameFailed),
            Some(SdExportError::RenameFailed),
            false,
        ),
        9 => (None, Some(SdExportError::FilenameCollision), true),
        _ => unreachable!("modulo ten is exhaustive"),
    }
}

fn assert_named_sd_error(error: SdExportError) {
    match error {
        SdExportError::FullMedia
        | SdExportError::TemporaryCreateFailed
        | SdExportError::WriteFailed
        | SdExportError::SyncFailed
        | SdExportError::CloseFailed
        | SdExportError::ReopenFailed
        | SdExportError::VerificationMismatch
        | SdExportError::FilenameCollision
        | SdExportError::RenameFailed => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_named_bbqr_error(error: BbqrError) {
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

fn assert_fixture_frames(part_len: usize, frames: &[Vec<u8>]) {
    match part_len {
        500 => {
            assert_eq!(frames.len(), fixture_usize(b"bbqr_single_frame_count: "));
            assert_eq!(frames[0], fixture_value(b"bbqr_single_frame_0: "));
        }
        80 => {
            assert_eq!(frames.len(), fixture_usize(b"bbqr_multi_frame_count: "));
            for (index, frame) in frames.iter().enumerate() {
                let prefix = format!("bbqr_multi_frame_{index}: ");
                assert_eq!(frame, fixture_value(prefix.as_bytes()));
            }
        }
        _ => {}
    }
}

fn bbqr_outcome(artifact: SelectedArtifact<'_>, part_len: usize) -> BbqrOutcome {
    let SelectedArtifact::FinalizedPsbt(psbt) = artifact else {
        return BbqrOutcome::NotApplicable;
    };
    let mut encoder = match psbt.bbqr(part_len) {
        Ok(encoder) => encoder,
        Err(error) => {
            assert_named_bbqr_error(error);
            return BbqrOutcome::Rejected(error);
        }
    };
    let declared = encoder.declared_parts();
    let mut output = [0xa5; MAX_FRAME_TEXT_BYTES];
    let mut frames = Vec::new();
    while let Some(metadata) = encoder
        .next_frame(&mut output)
        .expect("accepted M25 geometry must frame")
    {
        assert_eq!(metadata.declared_parts(), declared);
        assert_eq!(usize::from(metadata.part_index()), frames.len());
        assert_eq!(&output[..4], b"B$2P");
        frames.push(output[..metadata.frame_len()].to_vec());
    }
    assert_eq!(frames.len(), usize::from(declared));

    let mut assembled = [0u8; MAX_TOTAL_DECODED_BYTES];
    let mut reassembler = Reassembler::new(&mut assembled);
    for frame in &frames {
        reassembler
            .submit(frame)
            .expect("M25 frames must reassemble through unchanged M22");
    }
    assert_eq!(
        reassembler.payload().expect("complete M25 BBQr"),
        psbt.bytes()
    );
    assert_fixture_frames(part_len, &frames);
    BbqrOutcome::Frames(frames)
}

fn publish(
    artifact: SelectedArtifact<'_>,
    nonce_bytes: [u8; 16],
    nonce: ExportNonce,
    fault_control: u8,
) -> PublicationOutcome {
    let kind = artifact.kind();
    let final_name = artifact_name(kind, nonce_bytes, false);
    let temporary_name = artifact_name(kind, nonce_bytes, true);
    let other_kind = match kind {
        ExportArtifactKind::FinalizedPsbt => ExportArtifactKind::RawTransaction,
        ExportArtifactKind::RawTransaction => ExportArtifactKind::FinalizedPsbt,
    };
    let other_final_name = artifact_name(other_kind, nonce_bytes, false);
    let (injected, expected_error, collision) = fault(fault_control);
    let mut filesystem = MockSdFilesystem::new();
    assert!(filesystem.insert_existing(INPUT_NAME, golden_s0()));
    if collision {
        assert!(filesystem.insert_existing(&final_name, COLLISION_BYTES));
    }
    let final_before = filesystem
        .existing_file_bytes(&final_name)
        .map(<[u8]>::to_vec);
    let result = write_artifact(artifact, nonce, &mut filesystem, injected);
    assert_eq!(
        filesystem.existing_file_bytes(INPUT_NAME),
        Some(golden_s0())
    );
    assert_eq!(filesystem.existing_file_bytes(&other_final_name), None);

    match (&result, expected_error) {
        (Ok(receipt), None) => {
            assert_eq!(receipt.metadata(), artifact_metadata(artifact));
            assert_eq!(receipt.names().final_name().as_str(), final_name);
            assert_eq!(receipt.names().temporary_name().as_str(), temporary_name);
            assert_eq!(
                filesystem.existing_file_bytes(&final_name),
                Some(artifact_bytes(artifact))
            );
            assert_eq!(filesystem.existing_file_bytes(&temporary_name), None);
        }
        (Err(error), Some(expected)) => {
            assert_named_sd_error(*error);
            assert_eq!(*error, expected);
            assert_eq!(
                filesystem
                    .existing_file_bytes(&final_name)
                    .map(<[u8]>::to_vec),
                final_before,
                "a failed per-artifact call must not publish or replace a final"
            );
        }
        _ => panic!("fault control produced the wrong named outcome"),
    }

    PublicationOutcome::Attempted(Box::new(PublicationAttempt {
        result,
        events: filesystem.events().to_vec(),
        final_bytes: filesystem
            .existing_file_bytes(&final_name)
            .map(<[u8]>::to_vec),
        temporary_bytes: filesystem
            .existing_file_bytes(&temporary_name)
            .map(<[u8]>::to_vec),
        input_bytes: filesystem
            .existing_file_bytes(INPUT_NAME)
            .expect("immutable input remains")
            .to_vec(),
    }))
}

fn run_once(data: &[u8]) -> Outcome {
    let chosen_tier = tier(data.first().copied().unwrap_or(0));
    let kind = selected_kind(data.get(1).copied().unwrap_or(0));
    let fault_control = data.get(2).copied().unwrap_or(0);
    let part_selector = data.get(3).copied().unwrap_or(7);
    let part_len = PART_LENGTHS[usize::from(part_selector) % PART_LENGTHS.len()];
    let (nonce_bytes, export_nonce) = nonce(data.get(4..20).unwrap_or_default());

    let owner = ExportArtifacts::from_finalized(finalized(), chosen_tier)
        .expect("M25 finalized capability must bind");
    assert_eq!(owner.tier(), chosen_tier);
    let Some(artifact) = select_artifact(owner.artifacts(), kind) else {
        assert_eq!(chosen_tier, KitTier::QuantumShelter);
        assert_eq!(kind, ExportArtifactKind::FinalizedPsbt);
        return Outcome {
            tier: chosen_tier,
            selected_kind: kind,
            bbqr: BbqrOutcome::NotApplicable,
            publication: PublicationOutcome::UnavailableByTier,
        };
    };
    assert_eq!(artifact.kind(), kind);
    assert_metadata(kind, artifact_metadata(artifact));
    let bbqr = bbqr_outcome(artifact, part_len);
    let publication = publish(artifact, nonce_bytes, export_nonce, fault_control);
    Outcome {
        tier: chosen_tier,
        selected_kind: kind,
        bbqr,
        publication,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_CONTROL_BYTES {
        return;
    }
    let first = run_once(data);
    let second = run_once(data);
    assert_eq!(first, second);
});
