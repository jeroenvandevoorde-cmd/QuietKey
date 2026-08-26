//! M25 public-API export integration against its dedicated NEVER-FUND fixture.

use qk_bbqr::{Reassembler, MAX_FRAME_TEXT_BYTES, MAX_TOTAL_DECODED_BYTES};
use qk_descriptor::parse_descriptor_pair;
use qk_host_sim::{
    ExportArtifactKind, ExportArtifacts, ExportNonce, FinalizedPsbtArtifact, KitTier, MockFileKind,
    MockSdFilesystem, RawTransactionArtifact, ReviewReadyWorkflow, SdArtifactMetadata,
    SdArtifactNames, SdExportError, SdExportFault, SdLifecycleEvent, TierArtifacts,
};
use qk_psbt::InputSource;

#[path = "../../qk-psbt/src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &[u8] = include_bytes!("fixtures/m25_export.txt");
const FIXTURE_BYTES: usize = 14_624;
const FIXTURE_LF: usize = 111;
const FIXTURE_SHA256: &str = "8f93bbda0b46ea85ed9fed7175037139b06bd93d5f3e6593c08caafce6a4fc07";

fn global(name: &str) -> &'static str {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            let line = core::str::from_utf8(line).expect("fixture is UTF-8");
            line.strip_prefix(&format!("{name}: "))
        })
        .expect("fixture global field")
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex width");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex(value).try_into().expect("exact fixture field width")
}

fn usize_field(name: &str) -> usize {
    global(name).parse().expect("fixture usize")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = fixture_sha256::Sha256::new();
    hasher.update(bytes).expect("fixture hash update");
    hasher.finalize().expect("fixture hash finalization")
}

fn nonce() -> ExportNonce {
    ExportNonce::from_bytes(hex_array::<16>(global("export_nonce_hex")))
}

fn finalized() -> qk_host_sim::FinalizedTransaction {
    let descriptor = parse_descriptor_pair(
        global("receive_descriptor").as_bytes(),
        global("change_descriptor").as_bytes(),
    )
    .expect("M25 descriptor pair");
    let s0 = hex(global("initial_psbt_hex"));
    assert_eq!(s0.len(), usize_field("initial_psbt_len"));
    assert_eq!(sha256(&s0), hex_array::<32>(global("initial_psbt_sha256")));

    let mut workflow = ReviewReadyWorkflow::new(descriptor).expect("workflow construction");
    workflow
        .intake(&s0, InputSource::MicroSd)
        .expect("immutable M25 intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validate");
    workflow.construct_review().expect("construct review");
    let ready = workflow.review_ready().expect("review-ready result");
    assert_eq!(ready.s0_len(), s0.len());
    assert_eq!(ready.s0_sha256(), sha256(&s0));
    assert_eq!(ready.input_source(), InputSource::MicroSd);

    let finalized = workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("already threshold-complete M25 fixture");
    assert_eq!(
        finalized.finalized_psbt(),
        hex(global("finalized_psbt_hex"))
    );
    assert_eq!(finalized.raw_transaction(), hex(global("raw_tx_hex")));
    assert_eq!(finalized.txid(), hex_array::<32>(global("txid_raw_hex")));
    assert_eq!(finalized.wtxid(), hex_array::<32>(global("wtxid_raw_hex")));
    finalized
}

fn export(tier: KitTier) -> ExportArtifacts {
    ExportArtifacts::from_finalized(finalized(), tier).expect("M25 export binding")
}

fn assert_metadata(metadata: SdArtifactMetadata, kind: ExportArtifactKind, prefix: &str) {
    assert_eq!(metadata.kind(), kind);
    assert_eq!(
        metadata.serialized_len(),
        usize_field(&format!("{prefix}_len"))
    );
    assert_eq!(
        metadata.sha256(),
        hex_array::<32>(global(&format!("{prefix}_sha256")))
    );
    assert_eq!(metadata.txid(), hex_array::<32>(global("txid_raw_hex")));
    assert_eq!(metadata.wtxid(), hex_array::<32>(global("wtxid_raw_hex")));
}

fn assert_psbt_artifact(artifact: FinalizedPsbtArtifact<'_>) {
    assert_eq!(artifact.bytes(), hex(global("finalized_psbt_hex")));
    assert_metadata(
        artifact.metadata(),
        ExportArtifactKind::FinalizedPsbt,
        "finalized_psbt",
    );
}

fn assert_raw_artifact(artifact: RawTransactionArtifact<'_>) {
    assert_eq!(artifact.bytes(), hex(global("raw_tx_hex")));
    assert_metadata(
        artifact.metadata(),
        ExportArtifactKind::RawTransaction,
        "raw_tx",
    );
}

fn public_names(kind: ExportArtifactKind) -> SdArtifactNames {
    let owner = export(KitTier::SimpleRecovery);
    let mut filesystem = MockSdFilesystem::new();
    let receipt = match owner.artifacts() {
        TierArtifacts::SimpleRecovery {
            finalized_psbt,
            raw_transaction,
        } => match kind {
            ExportArtifactKind::FinalizedPsbt => {
                finalized_psbt.write_mock_sd(nonce(), &mut filesystem, None)
            }
            ExportArtifactKind::RawTransaction => {
                raw_transaction.write_mock_sd(nonce(), &mut filesystem, None)
            }
        },
        _ => panic!("Simple Recovery artifact shape"),
    }
    .expect("public name derivation through successful write");
    receipt.names().clone()
}

fn write_with_fault(
    kind: ExportArtifactKind,
    fault: Option<SdExportFault>,
    filesystem: &mut MockSdFilesystem,
) -> Result<qk_host_sim::SdPublishedArtifact, SdExportError> {
    let owner = export(KitTier::SimpleRecovery);
    match owner.artifacts() {
        TierArtifacts::SimpleRecovery {
            finalized_psbt,
            raw_transaction,
        } => match kind {
            ExportArtifactKind::FinalizedPsbt => {
                finalized_psbt.write_mock_sd(nonce(), filesystem, fault)
            }
            ExportArtifactKind::RawTransaction => {
                raw_transaction.write_mock_sd(nonce(), filesystem, fault)
            }
        },
        _ => panic!("Simple Recovery artifact shape"),
    }
}

fn artifact_len(kind: ExportArtifactKind) -> usize {
    match kind {
        ExportArtifactKind::FinalizedPsbt => usize_field("finalized_psbt_len"),
        ExportArtifactKind::RawTransaction => usize_field("raw_tx_len"),
    }
}

#[test]
fn fixture_identity_is_exact_and_contains_no_imported_secret() {
    assert_eq!(FIXTURE.len(), FIXTURE_BYTES);
    assert_eq!(
        FIXTURE.iter().filter(|byte| **byte == b'\n').count(),
        FIXTURE_LF
    );
    assert_eq!(FIXTURE.last(), Some(&b'\n'));
    assert!(!FIXTURE.contains(&b'\r'));
    assert_eq!(sha256(FIXTURE), hex_array::<32>(FIXTURE_SHA256));

    let text = core::str::from_utf8(FIXTURE).expect("fixture UTF-8");
    assert!(text.starts_with("# PERMANENTLY NEVER-FUND\n"));
    for forbidden in [
        "private_scalar_hex:",
        "private_key_hex:",
        "secret_key_hex:",
        "nonce_scalar_hex:",
        "role_a_seed_ascii:",
        "role_b_seed_ascii:",
        "role_c_seed_ascii:",
        "M24/NEVER-FUND",
    ] {
        assert!(
            !text.contains(forbidden),
            "forbidden fixture field {forbidden}"
        );
    }
}

#[test]
fn tier_exposure_and_bound_facts_are_exact() {
    for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
        let owner = export(tier);
        assert_eq!(owner.tier(), tier);
        match owner.artifacts() {
            TierArtifacts::SimpleRecovery {
                finalized_psbt,
                raw_transaction,
            }
            | TierArtifacts::Inheritance {
                finalized_psbt,
                raw_transaction,
            } => {
                assert_psbt_artifact(finalized_psbt);
                assert_raw_artifact(raw_transaction);
            }
            TierArtifacts::QuantumShelter { .. } => panic!("wrong tier exposure"),
        }
    }

    let owner = export(KitTier::QuantumShelter);
    assert_eq!(owner.tier(), KitTier::QuantumShelter);
    match owner.artifacts() {
        TierArtifacts::QuantumShelter { raw_transaction } => assert_raw_artifact(raw_transaction),
        _ => panic!("Quantum Shelter exposed a finalized PSBT"),
    }
}

#[test]
fn exact_names_and_successful_sd_lifecycles_preserve_input() {
    let owner = export(KitTier::SimpleRecovery);
    let (psbt, raw) = match owner.artifacts() {
        TierArtifacts::SimpleRecovery {
            finalized_psbt,
            raw_transaction,
        } => (finalized_psbt, raw_transaction),
        _ => panic!("Simple Recovery artifact shape"),
    };
    let input = hex(global("initial_psbt_hex"));
    let mut filesystem = MockSdFilesystem::new();
    assert!(filesystem.insert_existing("input.psbt", &input));

    let psbt_receipt = psbt
        .write_mock_sd(nonce(), &mut filesystem, None)
        .expect("finalized PSBT mock-SD publication");
    let raw_receipt = raw
        .write_mock_sd(nonce(), &mut filesystem, None)
        .expect("raw transaction mock-SD publication");

    assert_eq!(
        psbt_receipt.names().final_name().as_str(),
        global("finalized_psbt_final_name")
    );
    assert_eq!(
        psbt_receipt.names().temporary_name().as_str(),
        global("finalized_psbt_temporary_name")
    );
    assert_eq!(
        raw_receipt.names().final_name().as_str(),
        global("raw_tx_final_name")
    );
    assert_eq!(
        raw_receipt.names().temporary_name().as_str(),
        global("raw_tx_temporary_name")
    );
    assert_eq!(psbt_receipt.metadata(), psbt.metadata());
    assert_eq!(raw_receipt.metadata(), raw.metadata());

    assert_eq!(
        filesystem.file_bytes(psbt_receipt.names().final_name()),
        Some(psbt.bytes())
    );
    assert_eq!(
        filesystem.file_bytes(raw_receipt.names().final_name()),
        Some(raw.bytes())
    );
    assert_eq!(
        filesystem.file_kind(psbt_receipt.names().final_name()),
        Some(MockFileKind::Final)
    );
    assert_eq!(
        filesystem.file_kind(raw_receipt.names().final_name()),
        Some(MockFileKind::Final)
    );
    assert_eq!(
        filesystem.file_bytes(psbt_receipt.names().temporary_name()),
        None
    );
    assert_eq!(
        filesystem.file_bytes(raw_receipt.names().temporary_name()),
        None
    );
    assert_eq!(
        filesystem.existing_file_bytes("input.psbt"),
        Some(input.as_slice())
    );

    let expected_events = [
        SdLifecycleEvent::TemporaryCreated(ExportArtifactKind::FinalizedPsbt),
        SdLifecycleEvent::BytesWritten {
            artifact: ExportArtifactKind::FinalizedPsbt,
            bytes: psbt.bytes().len(),
            complete: true,
        },
        SdLifecycleEvent::FileSynced(ExportArtifactKind::FinalizedPsbt),
        SdLifecycleEvent::Closed(ExportArtifactKind::FinalizedPsbt),
        SdLifecycleEvent::Reopened(ExportArtifactKind::FinalizedPsbt),
        SdLifecycleEvent::Verified(ExportArtifactKind::FinalizedPsbt),
        SdLifecycleEvent::Renamed(ExportArtifactKind::FinalizedPsbt),
        SdLifecycleEvent::TemporaryCreated(ExportArtifactKind::RawTransaction),
        SdLifecycleEvent::BytesWritten {
            artifact: ExportArtifactKind::RawTransaction,
            bytes: raw.bytes().len(),
            complete: true,
        },
        SdLifecycleEvent::FileSynced(ExportArtifactKind::RawTransaction),
        SdLifecycleEvent::Closed(ExportArtifactKind::RawTransaction),
        SdLifecycleEvent::Reopened(ExportArtifactKind::RawTransaction),
        SdLifecycleEvent::Verified(ExportArtifactKind::RawTransaction),
        SdLifecycleEvent::Renamed(ExportArtifactKind::RawTransaction),
    ];
    assert_eq!(filesystem.events(), expected_events);
}

#[test]
fn every_named_sd_failure_is_atomic_and_preserves_input() {
    let faults = [
        (
            SdExportFault::TemporaryCreateFailed,
            SdExportError::TemporaryCreateFailed,
            None,
        ),
        (
            SdExportFault::FullMedia,
            SdExportError::FullMedia,
            Some(0usize),
        ),
        (
            SdExportFault::WriteFailed,
            SdExportError::WriteFailed,
            Some(1),
        ),
        (
            SdExportFault::SyncFailed,
            SdExportError::SyncFailed,
            Some(2),
        ),
        (
            SdExportFault::CloseFailed,
            SdExportError::CloseFailed,
            Some(2),
        ),
        (
            SdExportFault::ReopenFailed,
            SdExportError::ReopenFailed,
            Some(2),
        ),
        (
            SdExportFault::VerificationMismatch,
            SdExportError::VerificationMismatch,
            Some(2),
        ),
        (
            SdExportFault::RenameFailed,
            SdExportError::RenameFailed,
            Some(2),
        ),
    ];
    let input = hex(global("initial_psbt_hex"));

    for kind in [
        ExportArtifactKind::FinalizedPsbt,
        ExportArtifactKind::RawTransaction,
    ] {
        let names = public_names(kind);
        for (fault, expected_error, residue_class) in faults {
            let mut filesystem = MockSdFilesystem::new();
            assert!(filesystem.insert_existing("input.psbt", &input));
            assert_eq!(
                write_with_fault(kind, Some(fault), &mut filesystem),
                Err(expected_error)
            );
            assert_eq!(filesystem.file_bytes(names.final_name()), None);
            assert_ne!(
                filesystem.events().last(),
                Some(&SdLifecycleEvent::Renamed(kind))
            );
            match residue_class {
                None => assert_eq!(filesystem.file_bytes(names.temporary_name()), None),
                Some(0) => {
                    assert_eq!(filesystem.file_bytes(names.temporary_name()), Some(&[][..]));
                    assert_eq!(
                        filesystem.file_kind(names.temporary_name()),
                        Some(MockFileKind::Temporary)
                    );
                }
                Some(1) => assert_eq!(
                    filesystem
                        .file_bytes(names.temporary_name())
                        .map(<[u8]>::len),
                    Some(artifact_len(kind) / 2)
                ),
                Some(2) => assert_eq!(
                    filesystem
                        .file_bytes(names.temporary_name())
                        .map(<[u8]>::len),
                    Some(artifact_len(kind))
                ),
                _ => panic!("closed residue class"),
            }
            assert_eq!(
                filesystem.existing_file_bytes("input.psbt"),
                Some(input.as_slice())
            );
        }

        let mut collision = MockSdFilesystem::new();
        assert!(collision.insert_existing("input.psbt", &input));
        assert!(collision.insert_existing(names.final_name().as_str(), b"occupied"));
        assert_eq!(
            write_with_fault(kind, None, &mut collision),
            Err(SdExportError::FilenameCollision)
        );
        assert_eq!(
            collision.file_bytes(names.final_name()),
            Some(&b"occupied"[..])
        );
        assert_eq!(collision.file_bytes(names.temporary_name()), None);
        assert!(collision.events().is_empty());
        assert_eq!(
            collision.existing_file_bytes("input.psbt"),
            Some(input.as_slice())
        );
    }
}

fn assert_bbqr_fixture(artifact: FinalizedPsbtArtifact<'_>, label: &str) {
    let part_len = usize_field(&format!("bbqr_{label}_part_length"));
    let frame_count = usize_field(&format!("bbqr_{label}_frame_count"));
    let mut encoder = artifact.bbqr(part_len).expect("fixture BBQr geometry");
    assert_eq!(usize::from(encoder.declared_parts()), frame_count);

    let mut decoded = [0u8; MAX_TOTAL_DECODED_BYTES];
    let mut reassembler = Reassembler::new(&mut decoded);
    for index in 0..frame_count {
        let expected = global(&format!("bbqr_{label}_frame_{index}")).as_bytes();
        let mut output = [0xa5u8; MAX_FRAME_TEXT_BYTES];
        let frame = encoder
            .next_frame(&mut output)
            .expect("BBQr frame encode")
            .expect("expected frame");
        assert_eq!(usize::from(frame.declared_parts()), frame_count);
        assert_eq!(usize::from(frame.part_index()), index);
        assert_eq!(frame.frame_len(), expected.len());
        assert_eq!(&output[..frame.frame_len()], expected);
        assert!(output[frame.frame_len()..].iter().all(|byte| *byte == 0xa5));
        let progress = reassembler
            .submit(&output[..frame.frame_len()])
            .expect("exact frame reassembly");
        assert_eq!(usize::from(progress.received_parts), index + 1);
        assert_eq!(progress.complete, index + 1 == frame_count);
    }

    let mut exhausted = [0x5au8; MAX_FRAME_TEXT_BYTES];
    assert_eq!(encoder.next_frame(&mut exhausted), Ok(None));
    assert!(exhausted.iter().all(|byte| *byte == 0x5a));
    assert_eq!(
        reassembler.payload().expect("complete payload"),
        artifact.bytes()
    );
}

#[test]
fn exact_single_and_multipart_bbqr_frames_reassemble_to_finalized_psbt() {
    let owner = export(KitTier::SimpleRecovery);
    let psbt = match owner.artifacts() {
        TierArtifacts::SimpleRecovery { finalized_psbt, .. } => finalized_psbt,
        _ => panic!("Simple Recovery artifact shape"),
    };
    assert_bbqr_fixture(psbt, "single");
    assert_bbqr_fixture(psbt, "multi");
}
