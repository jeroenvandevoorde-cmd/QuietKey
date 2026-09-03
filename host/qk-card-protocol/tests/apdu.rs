#![allow(clippy::panic, clippy::unwrap_used)]

use qk_card_protocol::{
    encode_abort, encode_begin_provision, encode_commit, encode_export_a2, encode_get_info,
    encode_open_session, encode_read_d_chunk, encode_rejection, encode_select, encode_sign_digest,
    encode_success, encode_write_chunk, instruction_allows_rejection, parse_command,
    parse_response, A2Purpose, CommandRef, DescriptorSelector, EncodeError, EnvelopeRef,
    Instruction, Lifecycle, Media, Mode, Profile, ProtocolError, ResponseError, ResponseRef,
    SignRequest, StatusWord, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

const SESSION: [u8; 16] = [0x11; 16];
const WALLET: [u8; 32] = [0x22; 32];
const REVIEW: [u8; 32] = [0x33; 32];
const DIGEST: [u8; 32] = [0x44; 32];

fn envelope(sequence: u32) -> EnvelopeRef<'static> {
    EnvelopeRef::new(&SESSION, sequence)
}

#[test]
fn every_request_encoder_round_trips() {
    let mut output = [0u8; MAX_REQUEST_BYTES];
    let size = encode_select(&mut output).unwrap();
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]).unwrap(),
        CommandRef::Select
    );

    let size = encode_open_session(Mode::Normal, &SESSION, &mut output).unwrap();
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]).unwrap(),
        CommandRef::OpenSession {
            mode: Mode::Normal,
            session_id: &SESSION,
        }
    );

    let size = encode_get_info(envelope(1), &mut output).unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::GetInfo { .. })
    ));

    let size =
        encode_read_d_chunk(envelope(2), DescriptorSelector::Receive, 192, &mut output).unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::ReadDChunk {
            selector: DescriptorSelector::Receive,
            offset: 192,
            ..
        })
    ));

    let size = encode_export_a2(envelope(3), A2Purpose::Normal, &mut output).unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::ExportA2 {
            purpose: A2Purpose::Normal,
            ..
        })
    ));

    let size = encode_sign_digest(
        envelope(4),
        SignRequest {
            wallet_id: &WALLET,
            review_hash: &REVIEW,
            input_index: 9,
            branch: 1,
            child_index: 65_535,
            digest: &DIGEST,
        },
        &mut output,
    )
    .unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::SignDigest {
            input_index: 9,
            branch: 1,
            child_index: 65_535,
            ..
        })
    ));

    let nonce = [0x55; 12];
    let size = encode_begin_provision(envelope(5), 3, &nonce, &mut output).unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::BeginProvision { ordinal: 3, .. })
    ));

    let chunk = [0x66; 192];
    let size = encode_write_chunk(envelope(6), 576, &chunk, &mut output).unwrap();
    assert_eq!(size, MAX_REQUEST_BYTES);
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::WriteChunk {
            offset: 576,
            bytes,
            ..
        }) if bytes == chunk
    ));

    let size = encode_commit(envelope(7), &mut output).unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::Commit { .. })
    ));
    let size = encode_abort(envelope(8), &mut output).unwrap();
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..size]),
        Ok(CommandRef::Abort { .. })
    ));
}

#[test]
fn rejection_precedence_is_exact() {
    let collisions: &[(Media, &[u8], ProtocolError)] = &[
        (
            Media::Contactless,
            &[],
            ProtocolError::ContactInterfaceRequired,
        ),
        (Media::ContactT1, &[0x7f], ProtocolError::ClassNotSupported),
        (
            Media::ContactT1,
            &[0x80, 0x7f],
            ProtocolError::InstructionNotSupported,
        ),
        (
            Media::ContactT1,
            &[0x80, 0x10, 1, 0],
            ProtocolError::IncorrectP1P2,
        ),
        (
            Media::ContactT1,
            &[0x80, 0x10, 0, 0, 18],
            ProtocolError::WrongLength,
        ),
    ];
    for (media, command, expected) in collisions {
        assert_eq!(parse_command(*media, command), Err(*expected));
    }

    let mut output = [0u8; MAX_REQUEST_BYTES];
    let size = encode_open_session(Mode::Normal, &SESSION, &mut output).unwrap();
    output[5] = 2;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::ProtocolVersionMismatch)
    );
    output[5] = 1;
    output[6] = 0;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::ModeOrOperationRejected)
    );

    let size = encode_select(&mut output).unwrap();
    output[5] ^= 1;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::ModeOrOperationRejected)
    );
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size - 1]),
        Err(ProtocolError::WrongLength)
    );
}

#[test]
fn case4_framing_and_request_semantics_are_strict() {
    let mut output = [0u8; MAX_REQUEST_BYTES + 1];
    let size = encode_select(&mut output).unwrap();
    output[size - 1] = 1;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::WrongLength)
    );
    output[size - 1] = 0;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size - 1]),
        Err(ProtocolError::WrongLength)
    );
    output[size] = 0;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..=size]),
        Err(ProtocolError::WrongLength)
    );

    let size = encode_get_info(envelope(1), &mut output).unwrap();
    output[4] = 0;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::WrongLength)
    );

    let size = encode_get_info(envelope(1), &mut output).unwrap();
    output[22..26].fill(0);
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::SequenceRejected)
    );

    let size = encode_sign_digest(
        envelope(1),
        SignRequest {
            wallet_id: &WALLET,
            review_hash: &REVIEW,
            input_index: 0,
            branch: 1,
            child_index: 65_535,
            digest: &DIGEST,
        },
        &mut output,
    )
    .unwrap();
    output[5 + 21 + 68] = 2;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::DerivationPathRejected)
    );

    let size =
        encode_read_d_chunk(envelope(1), DescriptorSelector::Receive, 0, &mut output).unwrap();
    output[28] = 1;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::ModeOrOperationRejected)
    );

    let size = encode_begin_provision(envelope(1), 1, &[0x55; 12], &mut output).unwrap();
    output[26] = 0;
    assert_eq!(
        parse_command(Media::ContactT1, &output[..size]),
        Err(ProtocolError::ProvisioningOrderRejected)
    );
    assert_eq!(
        encode_write_chunk(envelope(1), 0, &[0u8; 191], &mut output),
        Err(EncodeError::ValueOutOfRange)
    );
    let final_write = encode_write_chunk(envelope(1), 768, &[0u8; 13], &mut output).unwrap();
    assert_eq!(final_write, 42);
    assert!(matches!(
        parse_command(Media::ContactT1, &output[..final_write]),
        Ok(CommandRef::WriteChunk {
            offset: 768,
            bytes,
            ..
        }) if bytes.len() == 13
    ));
}

fn assert_body_length_precedes_envelope(mut command: Vec<u8>) {
    let original_len = command.len();
    command[5] = 2;
    if original_len >= 27 {
        command[22..26].fill(0);
    }

    let mut longer = command.clone();
    longer[4] += 1;
    longer.insert(original_len - 1, 0);
    assert_eq!(
        parse_command(Media::ContactT1, &longer),
        Err(ProtocolError::WrongLength)
    );

    command[4] -= 1;
    command[original_len - 2] = 0;
    command.truncate(original_len - 1);
    assert_eq!(
        parse_command(Media::ContactT1, &command),
        Err(ProtocolError::WrongLength)
    );
}

#[test]
fn command_specific_length_precedes_version_and_sequence() {
    let mut output = [0u8; MAX_REQUEST_BYTES];

    let length = encode_open_session(Mode::Normal, &SESSION, &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_get_info(envelope(1), &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length =
        encode_read_d_chunk(envelope(1), DescriptorSelector::Receive, 0, &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_export_a2(envelope(1), A2Purpose::Normal, &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_sign_digest(
        envelope(1),
        SignRequest {
            wallet_id: &WALLET,
            review_hash: &REVIEW,
            input_index: 0,
            branch: 0,
            child_index: 0,
            digest: &DIGEST,
        },
        &mut output,
    )
    .unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_begin_provision(envelope(1), 1, &[0x55; 12], &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_write_chunk(envelope(1), 0, &[0x66; 192], &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_write_chunk(envelope(1), 768, &[0x66; 13], &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_commit(envelope(1), &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
    let length = encode_abort(envelope(1), &mut output).unwrap();
    assert_body_length_precedes_envelope(output[..length].to_vec());
}

#[test]
fn closed_per_instruction_status_sets_are_exact() {
    use ProtocolError as E;
    const ALL: [E; 19] = [
        E::ContactInterfaceRequired,
        E::ClassNotSupported,
        E::InstructionNotSupported,
        E::IncorrectP1P2,
        E::WrongLength,
        E::ProtocolVersionMismatch,
        E::SessionStateRejected,
        E::SessionIdMismatch,
        E::SequenceRejected,
        E::ModeOrOperationRejected,
        E::LifecycleRejected,
        E::ProvisioningOrderRejected,
        E::RecordRejected,
        E::WalletBindingRejected,
        E::DerivationPathRejected,
        E::ChildDerivationRejected,
        E::SigningBindingRejected,
        E::CryptographicOperationRejected,
        E::InternalIntegrityFailure,
    ];
    let cases: &[(Instruction, &[E])] = &[
        (
            Instruction::Select,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ModeOrOperationRejected,
            ],
        ),
        (
            Instruction::OpenSession,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
                E::InternalIntegrityFailure,
            ],
        ),
        (
            Instruction::GetInfo,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
            ],
        ),
        (
            Instruction::ReadDChunk,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
            ],
        ),
        (
            Instruction::ExportA2,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
            ],
        ),
        (
            Instruction::SignDigest,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
                E::WalletBindingRejected,
                E::DerivationPathRejected,
                E::ChildDerivationRejected,
                E::SigningBindingRejected,
                E::CryptographicOperationRejected,
            ],
        ),
        (
            Instruction::BeginProvision,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
                E::ProvisioningOrderRejected,
                E::InternalIntegrityFailure,
            ],
        ),
        (
            Instruction::WriteChunk,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
                E::ProvisioningOrderRejected,
                E::InternalIntegrityFailure,
            ],
        ),
        (
            Instruction::Commit,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
                E::ProvisioningOrderRejected,
                E::RecordRejected,
                E::WalletBindingRejected,
                E::CryptographicOperationRejected,
                E::InternalIntegrityFailure,
            ],
        ),
        (
            Instruction::Abort,
            &[
                E::ContactInterfaceRequired,
                E::ClassNotSupported,
                E::InstructionNotSupported,
                E::IncorrectP1P2,
                E::WrongLength,
                E::ProtocolVersionMismatch,
                E::SessionStateRejected,
                E::SessionIdMismatch,
                E::SequenceRejected,
                E::ModeOrOperationRejected,
                E::LifecycleRejected,
                E::InternalIntegrityFailure,
            ],
        ),
    ];
    let mut encoded = [0u8; 2];
    for (instruction, expected) in cases {
        let actual: Vec<E> = ALL
            .into_iter()
            .filter(|error| instruction_allows_rejection(*instruction, *error))
            .collect();
        assert_eq!(actual.as_slice(), *expected);
        for error in ALL {
            let size = encode_rejection(error, &mut encoded).unwrap();
            let parsed = parse_response(*instruction, &encoded[..size]);
            if expected.contains(&error) {
                assert_eq!(parsed, Ok(ResponseRef::Rejected(error)));
            } else {
                assert_eq!(parsed, Err(ResponseError::RejectionNotAllowed));
            }
        }
    }
    for (instruction, expected) in cases {
        assert_eq!(
            ALL.into_iter()
                .filter(|error| instruction_allows_rejection(*instruction, *error))
                .count(),
            expected.len()
        );
    }
}

#[test]
fn bodyless_rejections_and_every_success_shape_parse() {
    let mut output = [0u8; MAX_RESPONSE_BYTES];
    let size = encode_rejection(ProtocolError::RecordRejected, &mut output).unwrap();
    assert_eq!(
        parse_response(Instruction::Commit, &output[..size]).unwrap(),
        ResponseRef::Rejected(ProtocolError::RecordRejected)
    );

    let size = encode_success(None, &[], &mut output).unwrap();
    assert_eq!(
        parse_response(Instruction::Select, &output[..size]),
        Ok(ResponseRef::Select)
    );

    let size = encode_success(Some(envelope(0)), &[], &mut output).unwrap();
    assert!(matches!(
        parse_response(Instruction::OpenSession, &output[..size]),
        Ok(ResponseRef::OpenSession { .. })
    ));

    let mut info = [0u8; 137];
    info[0] = 1;
    info[1] = 1;
    info[2] = 2;
    info[3] = 1;
    info[4] = 2;
    info[57..61].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
    info[61] = 4;
    info[66..70].copy_from_slice(&[0x80, 0, 0, 2]);
    info[102] = 0x02;
    info[135..137].copy_from_slice(&0x000fu16.to_be_bytes());
    let size = encode_success(Some(envelope(1)), &info, &mut output).unwrap();
    assert!(matches!(
        parse_response(Instruction::GetInfo, &output[..size]),
        Ok(ResponseRef::GetInfo {
            profile: 1,
            allowed_operations: 0x000f,
            ..
        })
    ));

    let mut read = [0x77u8; 195];
    read[0] = DescriptorSelector::Receive.byte();
    read[1..3].copy_from_slice(&0u16.to_be_bytes());
    let size = encode_success(Some(envelope(2)), &read, &mut output).unwrap();
    assert_eq!(size, MAX_RESPONSE_BYTES);
    assert!(
        matches!(parse_response(Instruction::ReadDChunk, &output[..size]), Ok(ResponseRef::ReadDChunk { bytes, .. }) if bytes.len() == 192)
    );

    let mut a2 = [0x88u8; 33];
    a2[0] = A2Purpose::Normal.byte();
    let size = encode_success(Some(envelope(3)), &a2, &mut output).unwrap();
    assert!(matches!(
        parse_response(Instruction::ExportA2, &output[..size]),
        Ok(ResponseRef::ExportA2 {
            purpose: A2Purpose::Normal,
            ..
        })
    ));

    let mut signature = [0u8; 78];
    signature[0..32].copy_from_slice(&REVIEW);
    signature[32..36].copy_from_slice(&4u32.to_be_bytes());
    signature[36] = 0x02;
    signature[69] = 8;
    signature[70..78].copy_from_slice(&[0x30, 6, 2, 1, 1, 2, 1, 1]);
    let size = encode_success(Some(envelope(4)), &signature, &mut output).unwrap();
    assert!(
        matches!(parse_response(Instruction::SignDigest, &output[..size]), Ok(ResponseRef::SignDigest { input_index: 4, signature_der, .. }) if signature_der.len() == 8)
    );

    for instruction in [
        Instruction::BeginProvision,
        Instruction::Commit,
        Instruction::Abort,
    ] {
        let size = encode_success(Some(envelope(5)), &[], &mut output).unwrap();
        assert!(parse_response(instruction, &output[..size]).is_ok());
    }
    let size = encode_success(Some(envelope(6)), &192u16.to_be_bytes(), &mut output).unwrap();
    assert!(matches!(
        parse_response(Instruction::WriteChunk, &output[..size]),
        Ok(ResponseRef::WriteChunk {
            next_offset: 192,
            ..
        })
    ));
}

#[test]
fn response_parser_rejects_malformed_success_and_status() {
    assert_eq!(
        parse_response(Instruction::Select, &[]),
        Err(ResponseError::Truncated)
    );
    assert_eq!(
        parse_response(Instruction::Select, &[0x6f, 0x10]),
        Err(ResponseError::UnknownStatusWord)
    );
    assert_eq!(
        parse_response(Instruction::Select, &[1, 0x6f, 0x09]),
        Err(ResponseError::RejectionHasBody)
    );
    assert_eq!(
        parse_response(Instruction::Select, &[1, 0x90, 0x00]),
        Err(ResponseError::SuccessLength)
    );
    assert_eq!(StatusWord::InternalIntegrityFailure.bytes(), [0x6f, 0x0f]);
}

fn info_tail(lifecycle: u8, profile: u8, operations: u16) -> [u8; 137] {
    let mut info = [0u8; 137];
    info[0] = 1;
    info[1] = 1;
    info[2] = lifecycle;
    info[3] = profile;
    info[4] = 2;
    if lifecycle == Lifecycle::Committed.byte() {
        info[5..21].fill(0x11);
        info[21..53].fill(0x22);
        info[53..57].fill(0x33);
        info[57..61].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
        info[61] = 4;
        info[62..66].fill(0x33);
        info[66..70].copy_from_slice(&[0x80, 0, 0, 2]);
        info[70..102].fill(0x44);
        info[102] = 0x02;
        info[103..135].fill(0x55);
    }
    info[135..137].copy_from_slice(&operations.to_be_bytes());
    info
}

#[test]
fn response_semantics_are_lifecycle_and_instruction_coherent() {
    let mut output = [0u8; MAX_RESPONSE_BYTES];
    for (lifecycle, profile, operations) in [
        (Lifecycle::Unprovisioned, 0, 0x0011),
        (Lifecycle::Staging, 0, 0x00b1),
        (Lifecycle::Staging, 0, 0x00d1),
        (Lifecycle::Committed, Profile::SimpleRecovery.byte(), 0x0003),
        (Lifecycle::Committed, Profile::Inheritance.byte(), 0x0007),
        (Lifecycle::Committed, Profile::QuantumShelter.byte(), 0x000f),
        (Lifecycle::RetiredError, 0, 0x0001),
    ] {
        let tail = info_tail(lifecycle.byte(), profile, operations);
        let size = encode_success(Some(envelope(1)), &tail, &mut output).unwrap();
        assert!(matches!(
            parse_response(Instruction::GetInfo, &output[..size]),
            Ok(ResponseRef::GetInfo { .. })
        ));
    }

    for (lifecycle, profile, operations) in [
        (Lifecycle::Unprovisioned, 0, 0x0001),
        (Lifecycle::Staging, 0, 0x0011),
        (Lifecycle::Committed, Profile::SimpleRecovery.byte(), 0x00d1),
        (Lifecycle::RetiredError, 0, 0x000f),
    ] {
        let tail = info_tail(lifecycle.byte(), profile, operations);
        let size = encode_success(Some(envelope(1)), &tail, &mut output).unwrap();
        assert_eq!(
            parse_response(Instruction::GetInfo, &output[..size]),
            Err(ResponseError::SuccessField)
        );
    }

    let mut staged = info_tail(Lifecycle::Staging.byte(), 0, 0x00b1);
    staged[5] = 1;
    let size = encode_success(Some(envelope(1)), &staged, &mut output).unwrap();
    assert_eq!(
        parse_response(Instruction::GetInfo, &output[..size]),
        Err(ResponseError::SuccessField)
    );

    let mut committed = info_tail(
        Lifecycle::Committed.byte(),
        Profile::SimpleRecovery.byte(),
        0x0007,
    );
    committed[57] ^= 1;
    let size = encode_success(Some(envelope(1)), &committed, &mut output).unwrap();
    assert_eq!(
        parse_response(Instruction::GetInfo, &output[..size]),
        Err(ResponseError::SuccessField)
    );

    let size = encode_success(Some(envelope(1)), &191u16.to_be_bytes(), &mut output).unwrap();
    assert_eq!(
        parse_response(Instruction::WriteChunk, &output[..size]),
        Err(ResponseError::SuccessField)
    );
}
