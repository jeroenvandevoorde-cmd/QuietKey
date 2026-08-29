#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    BsmsErrorV2, WatchOnlyArtifactMetadataV2, WatchOnlyCoordinatorTierV2,
    WatchOnlyExportArtifactsV2, WatchOnlyExportErrorV2, WatchOnlyExportNonceV2,
    WatchOnlyMockSdFilesystemV2, WatchOnlySdExportErrorV2, WatchOnlySdExportFaultV2,
    WatchOnlySdLifecycleEventV2, BSMS_RECORD_BYTES_V2,
};
use qk_provisioning::ProvisioningArtifactsV2;

const FIXTURE: &[u8] = include_bytes!("../../host/qk-host-sim/tests/fixtures/watch_only_v2.txt");
const MAX_MUTATIONS: usize = 64;
const INPUT_NAME: &str = "immutable-input.psbt";
const INPUT_BYTES: &[u8] = b"immutable hostile-input copy";
const COLLISION_BYTES: &[u8] = b"pre-existing destination";

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicationOutcome {
    result: Result<(), WatchOnlySdExportErrorV2>,
    events: Vec<WatchOnlySdLifecycleEventV2>,
    final_bytes: Option<Vec<u8>>,
    temporary_bytes: Option<Vec<u8>>,
    input_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Outcome {
    Rejected(WatchOnlyExportErrorV2),
    Served {
        tier: WatchOnlyCoordinatorTierV2,
        bytes: Vec<u8>,
        metadata: WatchOnlyArtifactMetadataV2,
        reopened: Result<(), BsmsErrorV2>,
        publication: PublicationOutcome,
    },
}

fn field(prefix: &[u8]) -> &'static [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("registered v2 slice-6 public fixture field")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex<const N: usize>(encoded: &[u8]) -> [u8; N] {
    assert_eq!(encoded.len(), N * 2, "registered v2 slice-6 hex width");
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(encoded.chunks_exact(2)) {
        let high = hex_nibble(pair[0]).expect("registered v2 slice-6 high hex");
        let low = hex_nibble(pair[1]).expect("registered v2 slice-6 low hex");
        *slot = (high << 4) | low;
    }
    output
}

fn provisioning() -> ProvisioningArtifactsV2 {
    let receive: [u8; 306] = field(b"receive_descriptor: ")
        .try_into()
        .expect("registered receive descriptor width");
    let change: [u8; 306] = field(b"change_descriptor: ")
        .try_into()
        .expect("registered change descriptor width");
    let mut account_xpubs = [[0u8; 111]; 2];
    for (slot, start) in account_xpubs.iter_mut().zip([41usize, 180]) {
        slot.copy_from_slice(&receive[start..start + 111]);
    }
    ProvisioningArtifactsV2 {
        account_xpubs,
        descriptors: [receive, change],
        wallet_id: hex(field(b"wallet_id: ")),
        first_scripts: [
            hex(field(b"receive_0_script_pubkey: ")),
            hex(field(b"change_0_script_pubkey: ")),
        ],
        first_addresses: [
            field(b"receive_0_address: ")
                .try_into()
                .expect("registered receive address width"),
            field(b"change_0_address: ")
                .try_into()
                .expect("registered change address width"),
        ],
        a1_capsule: [0u8; 67],
    }
}

fn expected_bsms() -> [u8; BSMS_RECORD_BYTES_V2] {
    hex(field(b"bsms_bytes_hex: "))
}

fn tier(selector: u8) -> WatchOnlyCoordinatorTierV2 {
    match selector % 3 {
        0 => WatchOnlyCoordinatorTierV2::SimpleRecovery,
        1 => WatchOnlyCoordinatorTierV2::Inheritance,
        2 => WatchOnlyCoordinatorTierV2::QuantumShelter,
        _ => unreachable!("modulo three is exhaustive"),
    }
}

fn fault(
    selector: u8,
) -> (
    Option<WatchOnlySdExportFaultV2>,
    Option<WatchOnlySdExportErrorV2>,
    bool,
) {
    match selector % 10 {
        0 => (None, None, false),
        1 => (
            Some(WatchOnlySdExportFaultV2::FullMedia),
            Some(WatchOnlySdExportErrorV2::FullMedia),
            false,
        ),
        2 => (
            Some(WatchOnlySdExportFaultV2::TemporaryCreateFailed),
            Some(WatchOnlySdExportErrorV2::TemporaryCreateFailed),
            false,
        ),
        3 => (
            Some(WatchOnlySdExportFaultV2::WriteFailed),
            Some(WatchOnlySdExportErrorV2::WriteFailed),
            false,
        ),
        4 => (
            Some(WatchOnlySdExportFaultV2::SyncFailed),
            Some(WatchOnlySdExportErrorV2::SyncFailed),
            false,
        ),
        5 => (
            Some(WatchOnlySdExportFaultV2::CloseFailed),
            Some(WatchOnlySdExportErrorV2::CloseFailed),
            false,
        ),
        6 => (
            Some(WatchOnlySdExportFaultV2::ReopenFailed),
            Some(WatchOnlySdExportErrorV2::ReopenFailed),
            false,
        ),
        7 => (
            Some(WatchOnlySdExportFaultV2::VerificationMismatch),
            Some(WatchOnlySdExportErrorV2::VerificationMismatch),
            false,
        ),
        8 => (
            Some(WatchOnlySdExportFaultV2::RenameFailed),
            Some(WatchOnlySdExportErrorV2::RenameFailed),
            false,
        ),
        9 => (
            None,
            Some(WatchOnlySdExportErrorV2::FilenameCollision),
            true,
        ),
        _ => unreachable!("modulo ten is exhaustive"),
    }
}

fn nonce(control: &[u8]) -> ([u8; 16], WatchOnlyExportNonceV2) {
    let mut bytes = hex(field(b"caller_nonce_hex: "));
    for (slot, value) in bytes.iter_mut().zip(control.iter().copied()) {
        *slot = value;
    }
    (bytes, WatchOnlyExportNonceV2::from_bytes(bytes))
}

fn name(nonce: [u8; 16], temporary: bool) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::from("qk-");
    for byte in nonce {
        output.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        output.push(char::from(LOWER_HEX[usize::from(byte & 15)]));
    }
    output.push_str("-watch.bsms");
    if temporary {
        output.push_str(".tmp");
    }
    output
}

fn assert_bsms_error(error: BsmsErrorV2) {
    match error {
        BsmsErrorV2::InvalidDescriptorPair
        | BsmsErrorV2::WalletIdMismatch
        | BsmsErrorV2::FirstScriptMismatch
        | BsmsErrorV2::FirstAddressMismatch
        | BsmsErrorV2::DescriptorRoundTripMismatch
        | BsmsErrorV2::InvalidRecordLength
        | BsmsErrorV2::InvalidRecordEncoding
        | BsmsErrorV2::InvalidVersionLine
        | BsmsErrorV2::InvalidDescriptorLine
        | BsmsErrorV2::InvalidRestrictionsLine
        | BsmsErrorV2::InvalidAddressLine => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_export_error(error: WatchOnlyExportErrorV2) {
    match error {
        WatchOnlyExportErrorV2::QuantumShelterDescriptorExport
        | WatchOnlyExportErrorV2::HashingInvariant => {}
        WatchOnlyExportErrorV2::Bsms(inner) => assert_bsms_error(inner),
    }
    assert!(!error.to_string().is_empty());
}

fn assert_sd_error(error: WatchOnlySdExportErrorV2) {
    match error {
        WatchOnlySdExportErrorV2::FullMedia
        | WatchOnlySdExportErrorV2::TemporaryCreateFailed
        | WatchOnlySdExportErrorV2::WriteFailed
        | WatchOnlySdExportErrorV2::SyncFailed
        | WatchOnlySdExportErrorV2::CloseFailed
        | WatchOnlySdExportErrorV2::ReopenFailed
        | WatchOnlySdExportErrorV2::VerificationMismatch
        | WatchOnlySdExportErrorV2::FilenameCollision
        | WatchOnlySdExportErrorV2::RenameFailed => {}
    }
    assert!(!error.to_string().is_empty());
}

fn coordinate(selector: u8, value: u8, width: usize) -> usize {
    (usize::from(selector / 7) * 256 + usize::from(value)) % width
}

fn mutate_artifacts(
    mut artifacts: ProvisioningArtifactsV2,
    selector: u8,
    value: u8,
) -> ProvisioningArtifactsV2 {
    match selector % 7 {
        0 => {}
        1 => {
            let position = coordinate(selector, value, 2 * 306);
            artifacts.descriptors[position / 306][position % 306] ^= 1;
        }
        2 => artifacts.wallet_id[coordinate(selector, value, 32)] ^= 1,
        3 => {
            let position = coordinate(selector, value, 2 * 34);
            artifacts.first_scripts[position / 34][position % 34] ^= 1;
        }
        4 => {
            let position = coordinate(selector, value, 2 * 62);
            artifacts.first_addresses[position / 62][position % 62] ^= 1;
        }
        5 => {
            let position = coordinate(selector, value, 2 * 111);
            artifacts.account_xpubs[position / 111][position % 111] ^= 1;
        }
        6 => artifacts.a1_capsule[coordinate(selector, value, 67)] ^= 1,
        _ => unreachable!("modulo seven is exhaustive"),
    }
    artifacts
}

fn mutate_record(record: &mut [u8; BSMS_RECORD_BYTES_V2], control: &[u8]) {
    for pair in control.chunks_exact(2).take(MAX_MUTATIONS) {
        let position = (usize::from(pair[0]) * 256 + usize::from(pair[1])) % record.len();
        record[position] ^= pair[0].wrapping_add(pair[1]).wrapping_add(1);
    }
}

fn publish(
    artifact: qk_host_sim::WatchOnlyBsmsArtifactV2<'_>,
    nonce_bytes: [u8; 16],
    nonce: WatchOnlyExportNonceV2,
    selector: u8,
) -> PublicationOutcome {
    let final_name = name(nonce_bytes, false);
    let temporary_name = name(nonce_bytes, true);
    let (injected, expected, collision) = fault(selector);
    let mut filesystem = WatchOnlyMockSdFilesystemV2::new();
    assert!(filesystem.insert_existing(INPUT_NAME, INPUT_BYTES));
    if collision {
        assert!(filesystem.insert_existing(&final_name, COLLISION_BYTES));
    }
    let final_before = filesystem
        .existing_file_bytes(&final_name)
        .map(<[u8]>::to_vec);
    let result = artifact
        .write_mock_sd(nonce, &mut filesystem, injected)
        .map(|_| ());

    assert_eq!(
        filesystem.existing_file_bytes(INPUT_NAME),
        Some(INPUT_BYTES)
    );
    match (result, expected) {
        (Ok(()), None) => {
            assert_eq!(
                filesystem.existing_file_bytes(&final_name),
                Some(artifact.bytes().as_slice())
            );
            assert_eq!(filesystem.existing_file_bytes(&temporary_name), None);
        }
        (Err(actual), Some(expected)) => {
            assert_sd_error(actual);
            assert_eq!(actual, expected);
            assert_eq!(
                filesystem
                    .existing_file_bytes(&final_name)
                    .map(<[u8]>::to_vec),
                final_before
            );
        }
        _ => panic!("fault selector produced the wrong typed outcome"),
    }

    PublicationOutcome {
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
    }
}

fn run_once(data: &[u8]) -> Outcome {
    let chosen_tier = tier(data.first().copied().unwrap_or(0));
    let artifact_selector = data.get(1).copied().unwrap_or(0);
    let artifact_value = data.get(2).copied().unwrap_or(0);
    let fault_selector = data.get(3).copied().unwrap_or(0);
    let (nonce_bytes, export_nonce) = nonce(data.get(4..20).unwrap_or_default());
    let facts = mutate_artifacts(provisioning(), artifact_selector, artifact_value);
    let owner = match WatchOnlyExportArtifactsV2::from_provisioning(&facts, chosen_tier) {
        Ok(owner) => owner,
        Err(error) => {
            assert_export_error(error);
            if chosen_tier == WatchOnlyCoordinatorTierV2::QuantumShelter {
                assert_eq!(
                    error,
                    WatchOnlyExportErrorV2::QuantumShelterDescriptorExport
                );
            }
            return Outcome::Rejected(error);
        }
    };

    assert!(matches!(
        chosen_tier,
        WatchOnlyCoordinatorTierV2::SimpleRecovery | WatchOnlyCoordinatorTierV2::Inheritance
    ));
    let artifact = owner.artifact();
    assert_eq!(artifact.bytes(), &expected_bsms());
    let metadata = artifact.metadata();
    assert_eq!(metadata.serialized_len(), BSMS_RECORD_BYTES_V2);
    assert_eq!(metadata.wallet_id(), facts.wallet_id);
    assert_eq!(metadata.first_addresses(), facts.first_addresses);

    let mut reopened = *artifact.bytes();
    mutate_record(&mut reopened, data.get(20..).unwrap_or_default());
    let reopened_result = artifact.verify_reopened(&reopened);
    if reopened == *artifact.bytes() {
        assert_eq!(reopened_result, Ok(()));
    } else {
        let error = reopened_result.expect_err("changed reopened bytes must reject");
        assert_bsms_error(error);
    }

    let publication = publish(artifact, nonce_bytes, export_nonce, fault_selector);
    Outcome::Served {
        tier: chosen_tier,
        bytes: artifact.bytes().to_vec(),
        metadata,
        reopened: reopened_result,
        publication,
    }
}

fuzz_target!(|data: &[u8]| {
    let first = run_once(data);
    let second = run_once(data);
    assert_eq!(
        first, second,
        "v2 slice-6 hostile-input outcome must be repeatable"
    );
});
