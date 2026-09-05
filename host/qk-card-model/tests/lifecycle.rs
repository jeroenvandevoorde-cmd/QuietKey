//! Lifecycle, mode table and terminal-rejection coverage.

use qk_card_model::{
    CardModel, FaultPoint, ModelError, ModelLifecycle, ModelMode, ModelProfile, RECORD_BYTES,
};
use qk_card_protocol::{
    encode_abort, encode_begin_provision, encode_commit, encode_export_a2, encode_open_session,
    encode_read_d_chunk, encode_sign_digest, encode_write_chunk, A2Purpose, DescriptorSelector,
    EnvelopeRef, Media, ProtocolError, SignRequest, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

const FIXTURE: &str = include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
const NONCE: [u8; 12] = *b"QKV2S4NONCE1";
const SETUP_ID: [u8; 16] = [0x41; 16];
const NORMAL_ID: [u8; 16] = [0x42; 16];

fn fixture_record(profile: ModelProfile) -> [u8; RECORD_BYTES] {
    let prefix = match profile {
        ModelProfile::SimpleRecovery => "record_profile_01_hex: ",
        ModelProfile::Inheritance => "record_profile_02_hex: ",
        ModelProfile::QuantumShelter => "record_profile_03_hex: ",
    };
    let value = FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .expect("registered record");
    assert_eq!(value.len(), RECORD_BYTES * 2);
    let mut record = [0u8; RECORD_BYTES];
    for (output, pair) in record.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let text = core::str::from_utf8(pair).expect("ASCII hex");
        *output = u8::from_str_radix(text, 16).expect("fixture hex");
    }
    record
}

fn provision(model: &mut CardModel) -> [u8; RECORD_BYTES] {
    let record = fixture_record(ModelProfile::SimpleRecovery);
    model.select(true).expect("contact selection");
    model
        .open(1, ModelMode::Setup, SETUP_ID)
        .expect("setup open");
    model
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    let steps = [
        (0usize, 192usize),
        (192, 192),
        (384, 192),
        (576, 192),
        (768, 13),
    ];
    for (index, (offset, length)) in steps.iter().copied().enumerate() {
        assert_eq!(
            model.write_chunk(
                &SETUP_ID,
                2 + index as u32,
                offset as u16,
                &record[offset..offset + length]
            ),
            Ok((offset + length) as u16)
        );
    }
    model.commit(&SETUP_ID, 7).expect("commit");
    record
}

fn write_complete_record(model: &mut CardModel, record: &[u8; RECORD_BYTES]) {
    for (index, (offset, length)) in [
        (0usize, 192usize),
        (192, 192),
        (384, 192),
        (576, 192),
        (768, 13),
    ]
    .iter()
    .copied()
    .enumerate()
    {
        model
            .write_chunk(
                &SETUP_ID,
                2 + index as u32,
                offset as u16,
                &record[offset..offset + length],
            )
            .expect("write");
    }
}

fn commit_result(record: &[u8; RECORD_BYTES]) -> Result<(), ModelError> {
    let mut model = CardModel::new();
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    model
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    write_complete_record(&mut model, record);
    model.commit(&SETUP_ID, 7)
}

fn encoded_open() -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_open_session(ModelMode::Setup, &SETUP_ID, &mut output).expect("OPEN");
    output[..length].to_vec()
}

fn encoded_read(id: &'static [u8; 16], sequence: u32) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_read_d_chunk(
        EnvelopeRef::new(id, sequence),
        DescriptorSelector::Receive,
        0,
        &mut output,
    )
    .expect("READ_D");
    output[..length].to_vec()
}

fn encoded_a2(id: &'static [u8; 16], sequence: u32) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_export_a2(
        EnvelopeRef::new(id, sequence),
        A2Purpose::Setup,
        &mut output,
    )
    .expect("EXPORT_A2");
    output[..length].to_vec()
}

fn encoded_sign(id: &'static [u8; 16], sequence: u32, wallet: &[u8; 32]) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_sign_digest(
        EnvelopeRef::new(id, sequence),
        SignRequest {
            wallet_id: wallet,
            review_hash: &[0x58; 32],
            input_index: 0,
            branch: 0,
            child_index: 0,
            digest: &[0x59; 32],
        },
        &mut output,
    )
    .expect("SIGN");
    output[..length].to_vec()
}

fn encoded_begin(id: &'static [u8; 16], sequence: u32) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_begin_provision(EnvelopeRef::new(id, sequence), 1, &NONCE, &mut output)
        .expect("BEGIN");
    output[..length].to_vec()
}

fn encoded_write(id: &'static [u8; 16], sequence: u32) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_write_chunk(EnvelopeRef::new(id, sequence), 0, &[0x5a; 192], &mut output)
        .expect("WRITE");
    output[..length].to_vec()
}

fn encoded_commit(id: &'static [u8; 16], sequence: u32) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_commit(EnvelopeRef::new(id, sequence), &mut output).expect("COMMIT");
    output[..length].to_vec()
}

fn encoded_abort(id: &'static [u8; 16], sequence: u32) -> Vec<u8> {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let length = encode_abort(EnvelopeRef::new(id, sequence), &mut output).expect("ABORT");
    output[..length].to_vec()
}

fn assert_apdu_rejection(model: &mut CardModel, command: &[u8], expected: ProtocolError) {
    let mut response = [0xa5; MAX_RESPONSE_BYTES];
    assert_eq!(
        model.process_apdu(Media::ContactT1, command, &mut response),
        Err(expected)
    );
    assert_eq!(&response[..2], &expected.status_word().bytes());
    assert!(response[2..].iter().all(|byte| *byte == 0));
}

fn open_unprovisioned(mode: ModelMode) -> CardModel {
    let mut model = CardModel::new();
    model.select(true).expect("select");
    model.open(1, mode, SETUP_ID).expect("open");
    model
}

fn open_committed(mode: ModelMode) -> CardModel {
    let mut model = CardModel::new();
    let _ = provision(&mut model);
    model.select(true).expect("select");
    model.open(1, mode, SETUP_ID).expect("open");
    model
}

fn open_retired(mode: ModelMode) -> CardModel {
    let mut model = CardModel::new();
    let _ = provision(&mut model);
    model.inject_fault(FaultPoint::CorruptCommittedDigest);
    model.select(true).expect("select");
    assert_eq!(
        model.open(1, ModelMode::Normal, NORMAL_ID),
        Err(ModelError::InternalIntegrityFailure)
    );
    model.select(true).expect("retired select");
    model.open(1, mode, SETUP_ID).expect("retired open");
    model
}

#[test]
fn complete_setup_then_normal_read_export_and_sign() {
    let mut model = CardModel::new();
    let record = provision(&mut model);
    assert_eq!(model.lifecycle(), ModelLifecycle::Committed);

    model.select(true).expect("selection");
    model
        .open(1, ModelMode::Normal, NORMAL_ID)
        .expect("normal open");
    let info = model.info(&NORMAL_ID, 1).expect("info");
    assert_eq!(info.lifecycle, ModelLifecycle::Committed);
    assert_eq!(info.profile, ModelProfile::SimpleRecovery.byte());
    assert_eq!(info.role, 2);
    assert_eq!(info.allowed_operations, 0x000f);
    assert_eq!(&info.wallet_id, &record[23..55]);

    let mut descriptor = [0u8; 192];
    assert_eq!(
        model.read_descriptor(&NORMAL_ID, 2, 1, 0, &mut descriptor),
        Ok(192)
    );
    assert_eq!(&descriptor, &record[169..361]);
    assert_eq!(
        model.read_descriptor(&NORMAL_ID, 3, 1, 192, &mut descriptor),
        Ok(114)
    );
    assert_eq!(&descriptor[..114], &record[361..475]);
    assert_eq!(
        model.read_descriptor(&NORMAL_ID, 4, 2, 0, &mut descriptor),
        Ok(192)
    );
    assert_eq!(&descriptor, &record[475..667]);
    assert_eq!(
        model.read_descriptor(&NORMAL_ID, 5, 2, 192, &mut descriptor),
        Ok(114)
    );
    assert_eq!(&descriptor[..114], &record[667..781]);

    let mut a2 = [0u8; 32];
    assert_eq!(model.export_a2(&NORMAL_ID, 6, 2, &mut a2), Ok(()));
    assert_eq!(&a2, &record[137..169]);
    assert_eq!(
        model.export_a2(&NORMAL_ID, 7, 2, &mut a2),
        Err(ModelError::ModeOrOperationRejected)
    );
}

#[test]
fn every_rejection_terminates_and_requires_fresh_selection() {
    let mut model = CardModel::new();
    model.select(true).expect("selection");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(model.info(&SETUP_ID, 2), Err(ModelError::SequenceRejected));
    assert_eq!(
        model.open(1, ModelMode::Setup, SETUP_ID),
        Err(ModelError::SessionStateRejected)
    );
    model.select(true).expect("fresh selection");
    model
        .open(1, ModelMode::Setup, SETUP_ID)
        .expect("fresh open");
}

#[test]
fn committed_digest_failure_enters_absorbing_non_signing_state() {
    let mut model = CardModel::new();
    let _record = provision(&mut model);
    model.inject_fault(FaultPoint::CorruptCommittedDigest);
    model.select(true).expect("selection");
    assert_eq!(
        model.open(1, ModelMode::Normal, NORMAL_ID),
        Err(ModelError::InternalIntegrityFailure)
    );
    assert_eq!(model.lifecycle(), ModelLifecycle::RetiredError);
    model.select(true).expect("retired selection");
    model
        .open(1, ModelMode::Rescue, NORMAL_ID)
        .expect("info-only open");
    let info = model.info(&NORMAL_ID, 1).expect("retired info");
    assert_eq!(info.lifecycle, ModelLifecycle::RetiredError);
    assert_eq!(info.profile, 0);
    assert_eq!(info.allowed_operations, 1);
    assert_eq!(
        model
            .sign_digest(&NORMAL_ID, 2, &[0; 32], &[0; 32], 0, 0, 0, &[0; 32])
            .map(|_| ()),
        Err(ModelError::LifecycleRejected)
    );
}

#[test]
fn kit_restore_ordinal_three_requires_its_fresh_nonce() {
    let mut model = CardModel::new();
    model.select(true).expect("selection");
    model
        .open(1, ModelMode::KitRestore, SETUP_ID)
        .expect("open");
    assert_eq!(
        model.begin_provision(&SETUP_ID, 1, 2, NONCE),
        Err(ModelError::ProvisioningOrderRejected)
    );

    model.select(true).expect("fresh selection");
    model
        .open(1, ModelMode::KitRestore, SETUP_ID)
        .expect("open");
    assert_eq!(model.begin_provision(&SETUP_ID, 1, 3, NONCE), Ok(()));
}

#[test]
fn unprovisioned_and_staging_masks_and_transitions_are_exact() {
    let record = fixture_record(ModelProfile::QuantumShelter);
    let mut model = CardModel::new();
    for mode in [ModelMode::Normal, ModelMode::Rescue] {
        model.select(true).expect("select");
        assert_eq!(
            model.open(1, mode, SETUP_ID),
            Err(ModelError::LifecycleRejected)
        );
    }
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        model.info(&SETUP_ID, 1).expect("info").allowed_operations,
        0x0011
    );
    model
        .begin_provision(&SETUP_ID, 2, 1, NONCE)
        .expect("begin");
    assert_eq!(
        model.info(&SETUP_ID, 3).expect("info").allowed_operations,
        0x00b1
    );
    for (index, (offset, length)) in [
        (0usize, 192usize),
        (192, 192),
        (384, 192),
        (576, 192),
        (768, 13),
    ]
    .iter()
    .copied()
    .enumerate()
    {
        model
            .write_chunk(
                &SETUP_ID,
                4 + index as u32,
                offset as u16,
                &record[offset..offset + length],
            )
            .expect("write");
    }
    assert_eq!(
        model.info(&SETUP_ID, 9).expect("info").allowed_operations,
        0x00d1
    );
    model.abort(&SETUP_ID, 10).expect("abort");
    assert_eq!(model.lifecycle(), ModelLifecycle::Unprovisioned);
}

#[test]
fn fresh_begin_replaces_and_wipes_partial_staging() {
    let record = fixture_record(ModelProfile::Inheritance);
    let mut model = CardModel::new();
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    model
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    model
        .write_chunk(&SETUP_ID, 2, 0, &record[..192])
        .expect("first write");
    model
        .begin_provision(&SETUP_ID, 3, 1, NONCE)
        .expect("replacement begin");
    assert_eq!(
        model.commit(&SETUP_ID, 4),
        Err(ModelError::ProvisioningOrderRejected)
    );
}

#[test]
fn all_record_and_binding_checks_are_fail_closed() {
    let base = fixture_record(ModelProfile::SimpleRecovery);
    for index in [0usize, 4, 5, 6, 59, 63, 68, 104] {
        let mut changed = base;
        changed[index] ^= 0x01;
        assert_eq!(
            commit_result(&changed),
            Err(ModelError::RecordRejected),
            "record byte {index}"
        );
    }
    for scalar in [[0u8; 32], [0xffu8; 32]] {
        let mut changed = base;
        changed[105..137].copy_from_slice(&scalar);
        assert_eq!(commit_result(&changed), Err(ModelError::RecordRejected));
    }
    for index in [7usize, 23, 169, 475] {
        let mut changed = base;
        changed[index] ^= 1;
        assert_eq!(
            commit_result(&changed),
            Err(ModelError::WalletBindingRejected),
            "binding byte {index}"
        );
    }
}

#[test]
fn committed_is_terminal_and_masks_are_mode_specific() {
    let mut model = CardModel::new();
    let _ = provision(&mut model);
    for (mode, expected_mask) in [
        (ModelMode::Setup, 0x0007),
        (ModelMode::Normal, 0x000f),
        (ModelMode::KitRestore, 0x0003),
        (ModelMode::Rescue, 0x000f),
    ] {
        model.select(true).expect("select");
        model.open(1, mode, SETUP_ID).expect("open");
        assert_eq!(
            model.info(&SETUP_ID, 1).expect("info").allowed_operations,
            expected_mask
        );
        model.deselect();
    }
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        model.begin_provision(&SETUP_ID, 1, 1, NONCE),
        Err(ModelError::LifecycleRejected)
    );
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        model.write_chunk(&SETUP_ID, 1, 0, &[0; 192]),
        Err(ModelError::LifecycleRejected)
    );
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        model.commit(&SETUP_ID, 1),
        Err(ModelError::LifecycleRejected)
    );
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        model.abort(&SETUP_ID, 1),
        Err(ModelError::LifecycleRejected)
    );
}

#[test]
fn persistent_and_transaction_failures_enter_retired_error() {
    for fault in [FaultPoint::PersistentWrite, FaultPoint::Transaction] {
        let mut model = CardModel::new();
        model.select(true).expect("select");
        model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
        model.inject_fault(fault);
        assert_eq!(
            model.begin_provision(&SETUP_ID, 1, 1, NONCE),
            Err(ModelError::InternalIntegrityFailure)
        );
        assert_eq!(model.lifecycle(), ModelLifecycle::RetiredError);
    }

    let record = fixture_record(ModelProfile::SimpleRecovery);
    let mut write_failure = CardModel::new();
    write_failure.select(true).expect("select");
    write_failure
        .open(1, ModelMode::Setup, SETUP_ID)
        .expect("open");
    write_failure
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    write_failure.inject_fault(FaultPoint::PersistentWrite);
    assert_eq!(
        write_failure.write_chunk(&SETUP_ID, 2, 0, &record[..192]),
        Err(ModelError::InternalIntegrityFailure)
    );
    assert_eq!(write_failure.lifecycle(), ModelLifecycle::RetiredError);

    let mut commit_failure = CardModel::new();
    commit_failure.select(true).expect("select");
    commit_failure
        .open(1, ModelMode::Setup, SETUP_ID)
        .expect("open");
    commit_failure
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    write_complete_record(&mut commit_failure, &record);
    commit_failure.inject_fault(FaultPoint::Transaction);
    assert_eq!(
        commit_failure.commit(&SETUP_ID, 7),
        Err(ModelError::InternalIntegrityFailure)
    );
    assert_eq!(commit_failure.lifecycle(), ModelLifecycle::RetiredError);
}

#[test]
fn session_identity_sequence_version_and_command_cap_are_exact() {
    let mut model = CardModel::new();
    model.select(true).expect("select");
    assert_eq!(
        model.open(2, ModelMode::Setup, SETUP_ID),
        Err(ModelError::ProtocolVersionMismatch)
    );
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        model.info(&NORMAL_ID, 1),
        Err(ModelError::SessionIdMismatch)
    );
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    for sequence in 1..128 {
        model.info(&SETUP_ID, sequence).expect("within cap");
    }
    assert_eq!(
        model.info(&SETUP_ID, 128),
        Err(ModelError::SessionStateRejected)
    );
}

#[test]
fn retired_error_allows_only_info_and_lifecycle_precedes_all_other_semantics() {
    let mut model = CardModel::new();
    let _ = provision(&mut model);
    model.inject_fault(FaultPoint::CorruptCommittedDigest);
    model.select(true).expect("select");
    assert_eq!(
        model.open(1, ModelMode::Normal, NORMAL_ID),
        Err(ModelError::InternalIntegrityFailure)
    );

    model.select(true).expect("select");
    model
        .open(1, ModelMode::KitRestore, NORMAL_ID)
        .expect("open");
    let mut descriptor = [0u8; 192];
    assert_eq!(
        model.read_descriptor(&NORMAL_ID, 1, 9, 999, &mut descriptor),
        Err(ModelError::LifecycleRejected)
    );
    model.select(true).expect("select");
    model
        .open(1, ModelMode::KitRestore, NORMAL_ID)
        .expect("open");
    assert_eq!(
        model.export_a2(&NORMAL_ID, 1, 1, &mut [0u8; 32]),
        Err(ModelError::LifecycleRejected)
    );
    model.select(true).expect("select");
    model
        .open(1, ModelMode::KitRestore, NORMAL_ID)
        .expect("open");
    assert_eq!(
        model
            .sign_digest(&NORMAL_ID, 1, &[0; 32], &[0; 32], 0, 9, 999_999, &[0; 32])
            .map(|_| ()),
        Err(ModelError::LifecycleRejected)
    );

    model.select(true).expect("select");
    model.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    assert_eq!(
        model.read_descriptor(&NORMAL_ID, 1, 1, 0, &mut descriptor),
        Err(ModelError::LifecycleRejected)
    );
}

#[test]
fn per_command_semantic_precedence_collisions_are_exact() {
    let record = fixture_record(ModelProfile::SimpleRecovery);

    let mut duplicate_open = encoded_open();
    duplicate_open[6] = 9;
    let mut model = open_unprovisioned(ModelMode::Setup);
    assert_apdu_rejection(
        &mut model,
        &duplicate_open,
        ProtocolError::SessionStateRejected,
    );
    let mut model = CardModel::new();
    model.select(true).expect("select");
    assert_apdu_rejection(
        &mut model,
        &duplicate_open,
        ProtocolError::ModeOrOperationRejected,
    );

    for mut read in [
        {
            let mut value = encoded_read(&SETUP_ID, 1);
            value[26] = 9;
            value
        },
        {
            let mut value = encoded_read(&SETUP_ID, 1);
            value[27..29].copy_from_slice(&1u16.to_be_bytes());
            value
        },
    ] {
        assert_apdu_rejection(
            &mut CardModel::new(),
            &read,
            ProtocolError::SessionStateRejected,
        );
        let mut wrong_id = open_unprovisioned(ModelMode::Setup);
        read[6..22].copy_from_slice(&NORMAL_ID);
        assert_apdu_rejection(&mut wrong_id, &read, ProtocolError::SessionIdMismatch);
        let mut wrong_sequence = open_unprovisioned(ModelMode::Setup);
        read[6..22].copy_from_slice(&SETUP_ID);
        read[22..26].copy_from_slice(&2u32.to_be_bytes());
        assert_apdu_rejection(&mut wrong_sequence, &read, ProtocolError::SequenceRejected);
        let mut semantic = open_unprovisioned(ModelMode::Setup);
        read[22..26].copy_from_slice(&1u32.to_be_bytes());
        assert_apdu_rejection(&mut semantic, &read, ProtocolError::ModeOrOperationRejected);
    }

    let mut a2 = encoded_a2(&SETUP_ID, 1);
    a2[26] = 9;
    assert_apdu_rejection(
        &mut CardModel::new(),
        &a2,
        ProtocolError::SessionStateRejected,
    );
    let mut wrong_id = open_unprovisioned(ModelMode::Setup);
    a2[6..22].copy_from_slice(&NORMAL_ID);
    assert_apdu_rejection(&mut wrong_id, &a2, ProtocolError::SessionIdMismatch);
    let mut wrong_sequence = open_unprovisioned(ModelMode::Setup);
    a2[6..22].copy_from_slice(&SETUP_ID);
    a2[22..26].copy_from_slice(&2u32.to_be_bytes());
    assert_apdu_rejection(&mut wrong_sequence, &a2, ProtocolError::SequenceRejected);
    let mut semantic = open_committed(ModelMode::Setup);
    a2[22..26].copy_from_slice(&1u32.to_be_bytes());
    assert_apdu_rejection(&mut semantic, &a2, ProtocolError::ModeOrOperationRejected);

    let wallet: [u8; 32] = record[23..55].try_into().expect("fixture wallet");
    for mut sign in [
        {
            let mut value = encoded_sign(&SETUP_ID, 1, &wallet);
            value[94] = 2;
            value
        },
        {
            let mut value = encoded_sign(&SETUP_ID, 1, &wallet);
            value[95..99].copy_from_slice(&65_536u32.to_be_bytes());
            value
        },
    ] {
        assert_apdu_rejection(
            &mut CardModel::new(),
            &sign,
            ProtocolError::SessionStateRejected,
        );
        let mut wrong_id = open_committed(ModelMode::Normal);
        sign[6..22].copy_from_slice(&NORMAL_ID);
        assert_apdu_rejection(&mut wrong_id, &sign, ProtocolError::SessionIdMismatch);
        let mut wrong_sequence = open_committed(ModelMode::Normal);
        sign[6..22].copy_from_slice(&SETUP_ID);
        sign[22..26].copy_from_slice(&2u32.to_be_bytes());
        assert_apdu_rejection(&mut wrong_sequence, &sign, ProtocolError::SequenceRejected);
        let mut wrong_mode = open_committed(ModelMode::Setup);
        sign[22..26].copy_from_slice(&1u32.to_be_bytes());
        assert_apdu_rejection(
            &mut wrong_mode,
            &sign,
            ProtocolError::ModeOrOperationRejected,
        );
        let mut retired = open_retired(ModelMode::Normal);
        assert_apdu_rejection(&mut retired, &sign, ProtocolError::LifecycleRejected);
        let mut wrong_wallet = open_committed(ModelMode::Normal);
        sign[26] ^= 1;
        assert_apdu_rejection(
            &mut wrong_wallet,
            &sign,
            ProtocolError::WalletBindingRejected,
        );
        let mut semantic = open_committed(ModelMode::Normal);
        sign[26] ^= 1;
        assert_apdu_rejection(&mut semantic, &sign, ProtocolError::DerivationPathRejected);
    }

    let mut begin = encoded_begin(&SETUP_ID, 1);
    begin[26] = 9;
    assert_apdu_rejection(
        &mut CardModel::new(),
        &begin,
        ProtocolError::SessionStateRejected,
    );
    let mut wrong_id = open_unprovisioned(ModelMode::Setup);
    begin[6..22].copy_from_slice(&NORMAL_ID);
    assert_apdu_rejection(&mut wrong_id, &begin, ProtocolError::SessionIdMismatch);
    let mut wrong_sequence = open_unprovisioned(ModelMode::Setup);
    begin[6..22].copy_from_slice(&SETUP_ID);
    begin[22..26].copy_from_slice(&2u32.to_be_bytes());
    assert_apdu_rejection(&mut wrong_sequence, &begin, ProtocolError::SequenceRejected);
    let mut wrong_mode = open_committed(ModelMode::Normal);
    begin[22..26].copy_from_slice(&1u32.to_be_bytes());
    assert_apdu_rejection(
        &mut wrong_mode,
        &begin,
        ProtocolError::ModeOrOperationRejected,
    );
    let mut wrong_lifecycle = open_committed(ModelMode::Setup);
    assert_apdu_rejection(
        &mut wrong_lifecycle,
        &begin,
        ProtocolError::LifecycleRejected,
    );
    let mut semantic = open_unprovisioned(ModelMode::Setup);
    assert_apdu_rejection(
        &mut semantic,
        &begin,
        ProtocolError::ProvisioningOrderRejected,
    );

    let mut write = encoded_write(&SETUP_ID, 1);
    write[26..28].copy_from_slice(&1u16.to_be_bytes());
    assert_apdu_rejection(
        &mut CardModel::new(),
        &write,
        ProtocolError::SessionStateRejected,
    );
    let mut wrong_id = open_unprovisioned(ModelMode::Setup);
    write[6..22].copy_from_slice(&NORMAL_ID);
    assert_apdu_rejection(&mut wrong_id, &write, ProtocolError::SessionIdMismatch);
    let mut wrong_sequence = open_unprovisioned(ModelMode::Setup);
    write[6..22].copy_from_slice(&SETUP_ID);
    write[22..26].copy_from_slice(&2u32.to_be_bytes());
    assert_apdu_rejection(&mut wrong_sequence, &write, ProtocolError::SequenceRejected);
    let mut wrong_mode = open_committed(ModelMode::Normal);
    write[22..26].copy_from_slice(&1u32.to_be_bytes());
    assert_apdu_rejection(
        &mut wrong_mode,
        &write,
        ProtocolError::ModeOrOperationRejected,
    );
    let mut wrong_lifecycle = open_unprovisioned(ModelMode::Setup);
    assert_apdu_rejection(
        &mut wrong_lifecycle,
        &write,
        ProtocolError::LifecycleRejected,
    );
    let mut staging = open_unprovisioned(ModelMode::Setup);
    staging
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    write[22..26].copy_from_slice(&2u32.to_be_bytes());
    assert_apdu_rejection(
        &mut staging,
        &write,
        ProtocolError::ProvisioningOrderRejected,
    );

    for command in [encoded_commit(&SETUP_ID, 1), encoded_abort(&SETUP_ID, 1)] {
        let mut wrong_mode = open_committed(ModelMode::Normal);
        assert_apdu_rejection(
            &mut wrong_mode,
            &command,
            ProtocolError::ModeOrOperationRejected,
        );
        let mut wrong_lifecycle = open_unprovisioned(ModelMode::Setup);
        assert_apdu_rejection(
            &mut wrong_lifecycle,
            &command,
            ProtocolError::LifecycleRejected,
        );
        let mut retired = open_retired(ModelMode::Normal);
        assert_apdu_rejection(&mut retired, &command, ProtocolError::LifecycleRejected);
    }

    let mut open = CardModel::new();
    open.select(true).expect("select");
    open.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    assert_eq!(
        open.open(2, ModelMode::Setup, NORMAL_ID),
        Err(ModelError::ProtocolVersionMismatch)
    );

    let mut begin = CardModel::new();
    let _ = provision(&mut begin);
    begin.select(true).expect("select");
    begin.open(1, ModelMode::Normal, NORMAL_ID).expect("open");
    assert_eq!(
        begin.begin_provision(&NORMAL_ID, 1, 9, NONCE),
        Err(ModelError::ModeOrOperationRejected)
    );

    let mut write = CardModel::new();
    write.select(true).expect("select");
    write.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    write
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    write.inject_fault(FaultPoint::PersistentWrite);
    assert_eq!(
        write.write_chunk(&SETUP_ID, 2, 192, &record[..192]),
        Err(ModelError::ProvisioningOrderRejected)
    );

    let mut commit = CardModel::new();
    commit.select(true).expect("select");
    commit.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    commit
        .begin_provision(&SETUP_ID, 1, 1, NONCE)
        .expect("begin");
    commit.inject_fault(FaultPoint::Transaction);
    assert_eq!(
        commit.commit(&SETUP_ID, 2),
        Err(ModelError::ProvisioningOrderRejected)
    );

    let mut abort = CardModel::new();
    abort.select(true).expect("select");
    abort.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    abort.inject_fault(FaultPoint::PersistentWrite);
    assert_eq!(
        abort.abort(&SETUP_ID, 1),
        Err(ModelError::LifecycleRejected)
    );
}

#[cfg(feature = "fuzzing")]
#[test]
fn command_and_signature_caps_precede_identity_sequence_and_lifecycle() {
    let mut info = CardModel::new();
    info.select(true).expect("select");
    info.open(1, ModelMode::Setup, SETUP_ID).expect("open");
    info.set_command_count_for_test(qk_card_protocol::MAX_EXCHANGES);
    assert_eq!(
        info.info(&NORMAL_ID, 99),
        Err(ModelError::SessionStateRejected)
    );

    let mut sign = CardModel::new();
    let _ = provision(&mut sign);
    sign.inject_fault(FaultPoint::CorruptCommittedDigest);
    sign.select(true).expect("select");
    assert_eq!(
        sign.open(1, ModelMode::Normal, NORMAL_ID),
        Err(ModelError::InternalIntegrityFailure)
    );
    sign.select(true).expect("select");
    sign.open(1, ModelMode::Normal, NORMAL_ID)
        .expect("retired open");
    sign.set_signature_count_for_test(qk_card_protocol::MAX_SIGNATURES);
    assert_eq!(
        sign.sign_digest(&NORMAL_ID, 1, &[0; 32], &[0; 32], 0, 0, 0, &[0; 32])
            .map(|_| ()),
        Err(ModelError::LifecycleRejected)
    );
}

#[test]
fn model_error_names_and_status_words_are_closed() {
    for (error, name, status) in [
        (
            ModelError::ProtocolVersionMismatch,
            "ProtocolVersionMismatch",
            0x6f01,
        ),
        (
            ModelError::ContactInterfaceRequired,
            "ContactInterfaceRequired",
            0x6f02,
        ),
        (
            ModelError::SessionStateRejected,
            "SessionStateRejected",
            0x6f03,
        ),
        (ModelError::SessionIdMismatch, "SessionIdMismatch", 0x6f04),
        (ModelError::SequenceRejected, "SequenceRejected", 0x6f05),
        (
            ModelError::ModeOrOperationRejected,
            "ModeOrOperationRejected",
            0x6f06,
        ),
        (ModelError::LifecycleRejected, "LifecycleRejected", 0x6f07),
        (
            ModelError::ProvisioningOrderRejected,
            "ProvisioningOrderRejected",
            0x6f08,
        ),
        (ModelError::RecordRejected, "RecordRejected", 0x6f09),
        (
            ModelError::WalletBindingRejected,
            "WalletBindingRejected",
            0x6f0a,
        ),
        (
            ModelError::DerivationPathRejected,
            "DerivationPathRejected",
            0x6f0b,
        ),
        (
            ModelError::ChildDerivationRejected,
            "ChildDerivationRejected",
            0x6f0c,
        ),
        (
            ModelError::SigningBindingRejected,
            "SigningBindingRejected",
            0x6f0d,
        ),
        (
            ModelError::CryptographicOperationRejected,
            "CryptographicOperationRejected",
            0x6f0e,
        ),
        (
            ModelError::InternalIntegrityFailure,
            "InternalIntegrityFailure",
            0x6f0f,
        ),
    ] {
        assert_eq!(error.name(), name);
        assert_eq!(error.to_string(), name);
        assert_eq!(error.status_word(), status);
    }
}
