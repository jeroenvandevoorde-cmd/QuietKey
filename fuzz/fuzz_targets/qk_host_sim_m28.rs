#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    BsmsError, KitTier, WatchOnlyArtifactMetadata, WatchOnlyExportArtifacts, WatchOnlyExportError,
    WatchOnlyExportNonce, WatchOnlyMockSdFilesystem, WatchOnlySdExportError,
    WatchOnlySdExportFault, WatchOnlySdLifecycleEvent, BSMS_RECORD_BYTES,
};
use qk_provisioning::ProvisioningArtifacts;

const FIXTURE: &[u8] = include_bytes!("../../host/qk-host-sim/tests/fixtures/m28_watch_only.txt");
const MAX_MUTATIONS: usize = 64;
const INPUT_NAME: &str = "immutable-input.psbt";
const INPUT_BYTES: &[u8] = b"immutable hostile-input copy";
const COLLISION_BYTES: &[u8] = b"pre-existing destination";

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicationOutcome {
    result: Result<(), WatchOnlySdExportError>,
    events: Vec<WatchOnlySdLifecycleEvent>,
    final_bytes: Option<Vec<u8>>,
    temporary_bytes: Option<Vec<u8>>,
    input_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Outcome {
    Rejected(WatchOnlyExportError),
    Served {
        tier: KitTier,
        bytes: Vec<u8>,
        metadata: WatchOnlyArtifactMetadata,
        reopened: Result<(), BsmsError>,
        publication: PublicationOutcome,
    },
}

fn field(prefix: &[u8]) -> &'static [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("registered M28 public fixture field")
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
    assert_eq!(encoded.len(), N * 2, "registered M28 hex width");
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(encoded.chunks_exact(2)) {
        let high = hex_nibble(pair[0]).expect("registered M28 high hex");
        let low = hex_nibble(pair[1]).expect("registered M28 low hex");
        *slot = (high << 4) | low;
    }
    output
}

fn provisioning() -> ProvisioningArtifacts {
    let receive: [u8; 445] = field(b"receive_descriptor: ")
        .try_into()
        .expect("registered receive descriptor width");
    let change: [u8; 445] = field(b"change_descriptor: ")
        .try_into()
        .expect("registered change descriptor width");
    let mut account_xpubs = [[0u8; 111]; 3];
    for (slot, start) in account_xpubs.iter_mut().zip([41usize, 180, 319]) {
        slot.copy_from_slice(&receive[start..start + 111]);
    }
    ProvisioningArtifacts {
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

fn expected_bsms() -> [u8; BSMS_RECORD_BYTES] {
    hex(field(b"bsms_bytes_hex: "))
}

fn tier(selector: u8) -> KitTier {
    match selector % 3 {
        0 => KitTier::SimpleRecovery,
        1 => KitTier::Inheritance,
        2 => KitTier::QuantumShelter,
        _ => unreachable!("modulo three is exhaustive"),
    }
}

fn fault(
    selector: u8,
) -> (
    Option<WatchOnlySdExportFault>,
    Option<WatchOnlySdExportError>,
    bool,
) {
    match selector % 10 {
        0 => (None, None, false),
        1 => (
            Some(WatchOnlySdExportFault::FullMedia),
            Some(WatchOnlySdExportError::FullMedia),
            false,
        ),
        2 => (
            Some(WatchOnlySdExportFault::TemporaryCreateFailed),
            Some(WatchOnlySdExportError::TemporaryCreateFailed),
            false,
        ),
        3 => (
            Some(WatchOnlySdExportFault::WriteFailed),
            Some(WatchOnlySdExportError::WriteFailed),
            false,
        ),
        4 => (
            Some(WatchOnlySdExportFault::SyncFailed),
            Some(WatchOnlySdExportError::SyncFailed),
            false,
        ),
        5 => (
            Some(WatchOnlySdExportFault::CloseFailed),
            Some(WatchOnlySdExportError::CloseFailed),
            false,
        ),
        6 => (
            Some(WatchOnlySdExportFault::ReopenFailed),
            Some(WatchOnlySdExportError::ReopenFailed),
            false,
        ),
        7 => (
            Some(WatchOnlySdExportFault::VerificationMismatch),
            Some(WatchOnlySdExportError::VerificationMismatch),
            false,
        ),
        8 => (
            Some(WatchOnlySdExportFault::RenameFailed),
            Some(WatchOnlySdExportError::RenameFailed),
            false,
        ),
        9 => (None, Some(WatchOnlySdExportError::FilenameCollision), true),
        _ => unreachable!("modulo ten is exhaustive"),
    }
}

fn nonce(control: &[u8]) -> ([u8; 16], WatchOnlyExportNonce) {
    let mut bytes = hex(field(b"caller_nonce_hex: "));
    for (slot, value) in bytes.iter_mut().zip(control.iter().copied()) {
        *slot = value;
    }
    (bytes, WatchOnlyExportNonce::from_bytes(bytes))
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

fn assert_bsms_error(error: BsmsError) {
    match error {
        BsmsError::InvalidDescriptorPair
        | BsmsError::WalletIdMismatch
        | BsmsError::FirstScriptMismatch
        | BsmsError::FirstAddressMismatch
        | BsmsError::DescriptorRoundTripMismatch
        | BsmsError::InvalidRecordLength
        | BsmsError::InvalidRecordEncoding
        | BsmsError::InvalidVersionLine
        | BsmsError::InvalidDescriptorLine
        | BsmsError::InvalidRestrictionsLine
        | BsmsError::InvalidAddressLine => {}
    }
    assert!(!error.to_string().is_empty());
}

fn assert_export_error(error: WatchOnlyExportError) {
    match error {
        WatchOnlyExportError::QuantumShelterDescriptorExport
        | WatchOnlyExportError::HashingInvariant => {}
        WatchOnlyExportError::Bsms(inner) => assert_bsms_error(inner),
    }
    assert!(!error.to_string().is_empty());
}

fn assert_sd_error(error: WatchOnlySdExportError) {
    match error {
        WatchOnlySdExportError::FullMedia
        | WatchOnlySdExportError::TemporaryCreateFailed
        | WatchOnlySdExportError::WriteFailed
        | WatchOnlySdExportError::SyncFailed
        | WatchOnlySdExportError::CloseFailed
        | WatchOnlySdExportError::ReopenFailed
        | WatchOnlySdExportError::VerificationMismatch
        | WatchOnlySdExportError::FilenameCollision
        | WatchOnlySdExportError::RenameFailed => {}
    }
    assert!(!error.to_string().is_empty());
}

fn mutate_artifacts(
    mut artifacts: ProvisioningArtifacts,
    selector: u8,
    value: u8,
) -> ProvisioningArtifacts {
    match selector % 5 {
        0 => {}
        1 => artifacts.descriptors[0][usize::from(value) % 445] ^= 1,
        2 => artifacts.wallet_id[usize::from(value) % 32] ^= 1,
        3 => artifacts.first_scripts[usize::from(value & 1)][usize::from(value) % 34] ^= 1,
        4 => artifacts.first_addresses[usize::from(value & 1)][usize::from(value) % 62] ^= 1,
        _ => unreachable!("modulo five is exhaustive"),
    }
    artifacts
}

fn mutate_record(record: &mut [u8; BSMS_RECORD_BYTES], control: &[u8]) {
    for pair in control.chunks_exact(2).take(MAX_MUTATIONS) {
        let position = (usize::from(pair[0]) * 256 + usize::from(pair[1])) % record.len();
        record[position] ^= pair[0].wrapping_add(pair[1]).wrapping_add(1);
    }
}

fn publish(
    artifact: qk_host_sim::WatchOnlyBsmsArtifact<'_>,
    nonce_bytes: [u8; 16],
    nonce: WatchOnlyExportNonce,
    selector: u8,
) -> PublicationOutcome {
    let final_name = name(nonce_bytes, false);
    let temporary_name = name(nonce_bytes, true);
    let (injected, expected, collision) = fault(selector);
    let mut filesystem = WatchOnlyMockSdFilesystem::new();
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
    let owner = match WatchOnlyExportArtifacts::from_provisioning(&facts, chosen_tier) {
        Ok(owner) => owner,
        Err(error) => {
            assert_export_error(error);
            if chosen_tier == KitTier::QuantumShelter {
                assert_eq!(error, WatchOnlyExportError::QuantumShelterDescriptorExport);
            }
            return Outcome::Rejected(error);
        }
    };

    assert!(matches!(
        chosen_tier,
        KitTier::SimpleRecovery | KitTier::Inheritance
    ));
    let artifact = owner.artifact();
    assert_eq!(artifact.bytes(), &expected_bsms());
    let metadata = artifact.metadata();
    assert_eq!(metadata.serialized_len(), BSMS_RECORD_BYTES);
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
        "M28 hostile-input outcome must be repeatable"
    );
});
