#![allow(clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use qk_card_protocol::{
    parse_command, parse_record, parse_response, A2Purpose, CommandRef, DescriptorSelector,
    Instruction, Media, Mode, Profile, ResponseRef, DESCRIPTOR_BYTES, RECORD_BYTES,
};

const FIXTURE: &str = include_str!("fixtures/card_protocol_v1.txt");
const SETUP_SESSION: [u8; 16] = [0xa1; 16];
const NORMAL_SESSION: [u8; 16] = [0xb2; 16];

fn fixture() -> BTreeMap<&'static str, &'static str> {
    let fields: BTreeMap<_, _> = FIXTURE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once(": ").unwrap())
        .collect();
    assert_eq!(fields.len(), 81);
    fields
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            ((high << 4) | low) as u8
        })
        .collect()
}

fn bytes(fields: &BTreeMap<&str, &str>, name: &str) -> Vec<u8> {
    decode_hex(fields.get(name).unwrap())
}

fn manual_case4(cla: u8, ins: u8, data: &[u8]) -> Vec<u8> {
    let mut command = vec![cla, ins, 0, 0, u8::try_from(data.len()).unwrap()];
    command.extend_from_slice(data);
    command.push(0);
    command
}

fn envelope(session: &[u8; 16], sequence: u32) -> Vec<u8> {
    let mut data = vec![1];
    data.extend_from_slice(session);
    data.extend_from_slice(&sequence.to_be_bytes());
    data
}

fn request(ins: u8, session: &[u8; 16], sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut data = envelope(session, sequence);
    data.extend_from_slice(body);
    manual_case4(0x80, ins, &data)
}

fn response(session: &[u8; 16], sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut data = envelope(session, sequence);
    data.extend_from_slice(body);
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

fn assert_envelope(envelope: qk_card_protocol::EnvelopeRef<'_>, session: &[u8; 16], sequence: u32) {
    assert_eq!(envelope.session_id(), session);
    assert_eq!(envelope.sequence(), sequence);
}

#[test]
fn provenance_semantic_facts_and_records_are_complete() {
    assert!(FIXTURE.contains("# PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL\n"));
    assert!(FIXTURE.contains("15,601 bytes, 81 LF, final LF, no CR"));
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    let fields = fixture();
    assert_eq!(
        fields["format"],
        "QUIETKEY_CARD_S1_COMPLETE_PUBLIC_FACTS_V1"
    );
    assert_eq!(
        fields["funding_status"],
        "PERMANENTLY NEVER-FUND TEST MATERIAL"
    );
    for profile in ["01", "02", "03"] {
        assert_eq!(
            fields[&*format!("qk_core_profile_{profile}_bind_outcome")],
            "BoundNormalCardBDataV2"
        );
    }
    assert_eq!(fields["qk_core_info_lifecycle"], "Committed");
    assert_eq!(fields["qk_core_info_role"], "KeyCardB");
    assert_eq!(fields["qk_core_info_allowed_operations_hex"], "000f");
    assert_eq!(
        fields["qk_core_bound_wallet_id_hex"],
        fields["wallet_id_hex"]
    );
    assert_eq!(
        fields["qk_core_bound_account_xpub_text"],
        fields["account_xpub_text"]
    );
    assert_eq!(
        fields["qk_core_bound_receive_descriptor"],
        fields["receive_descriptor"]
    );
    assert_eq!(
        fields["qk_core_bound_change_descriptor"],
        fields["change_descriptor"]
    );
    assert_eq!(fields["qk_core_bound_a2_hex"], fields["a2_hex"]);
    assert_eq!(fields["qk_core_role_b_input_index"], "0");
    assert_eq!(
        fields["qk_core_role_b_public_key_hex"],
        fields["route_public_key_hex"]
    );
    assert_eq!(
        fields["qk_core_role_b_signature_der_hex"],
        fields["signature_der_hex"]
    );
    assert_eq!(
        fields["qk_core_role_b_signature_outcome"],
        "AcceptedAfterRevalidation"
    );

    let wallet = bytes(&fields, "wallet_id_hex");
    let instance = bytes(&fields, "instance_id_hex");
    let fingerprint = bytes(&fields, "account_origin_fingerprint_hex");
    let xprv = bytes(&fields, "account_xprv_raw_hex");
    let a2 = bytes(&fields, "a2_hex");
    let receive = fields["receive_descriptor"].as_bytes();
    let change = fields["change_descriptor"].as_bytes();
    assert_eq!(receive.len(), DESCRIPTOR_BYTES);
    assert_eq!(change.len(), DESCRIPTOR_BYTES);
    let profiles = [
        ("record_profile_01_hex", Profile::SimpleRecovery),
        ("record_profile_02_hex", Profile::Inheritance),
        ("record_profile_03_hex", Profile::QuantumShelter),
    ];
    let mut records = Vec::new();
    for (name, expected_profile) in profiles {
        let raw = bytes(&fields, name);
        assert_eq!(raw.len(), RECORD_BYTES);
        let record = parse_record(&raw).unwrap();
        assert_eq!(record.profile(), expected_profile);
        assert_eq!(record.instance_id(), instance.as_slice());
        assert_eq!(record.wallet_id(), wallet.as_slice());
        assert_eq!(record.origin_fingerprint(), fingerprint.as_slice());
        assert_eq!(record.account_xprv().bytes(), xprv.as_slice());
        assert_eq!(record.a2(), a2.as_slice());
        assert_eq!(record.receive_descriptor(), receive);
        assert_eq!(record.change_descriptor(), change);
        records.push(raw);
    }
    for (offset, first) in records[0].iter().enumerate() {
        if offset == 5 {
            assert_eq!(
                [records[0][offset], records[1][offset], records[2][offset]],
                [1, 2, 3]
            );
        } else {
            assert_eq!(*first, records[1][offset]);
            assert_eq!(records[1][offset], records[2][offset]);
        }
    }
}

#[test]
fn every_request_and_response_is_manually_reconstructed_and_typed() {
    let fields = fixture();
    let record = bytes(&fields, "record_profile_01_hex");
    let wallet = bytes(&fields, "wallet_id_hex");
    let nonce = bytes(&fields, "provisioning_nonce_hex");
    let review = bytes(&fields, "review_hash_hex");
    let digest = bytes(&fields, "digest_hex");
    let public_key = bytes(&fields, "route_public_key_hex");
    let signature = bytes(&fields, "signature_der_hex");
    let a2 = bytes(&fields, "a2_hex");
    let xpub = bytes(&fields, "account_xpub_raw_hex");
    let instance = bytes(&fields, "instance_id_hex");
    let fingerprint = bytes(&fields, "account_origin_fingerprint_hex");

    let select = vec![
        0x00, 0xa4, 0x04, 0x00, 0x06, 0xf0, 0x51, 0x4b, 0x32, 0x42, 0x01, 0x00,
    ];
    for prefix in ["setup", "normal"] {
        assert_eq!(
            bytes(&fields, &format!("{prefix}_select_request_hex")),
            select
        );
        assert_eq!(
            bytes(&fields, &format!("{prefix}_select_response_hex")),
            [0x90, 0]
        );
        assert!(matches!(
            parse_command(Media::ContactT1, &select).unwrap(),
            CommandRef::Select
        ));
        assert!(matches!(
            parse_response(Instruction::Select, &[0x90, 0]).unwrap(),
            ResponseRef::Select
        ));
    }

    for (prefix, mode, session) in [
        ("setup", Mode::Setup, &SETUP_SESSION),
        ("normal", Mode::Normal, &NORMAL_SESSION),
    ] {
        let mut open_body = vec![1, mode.byte()];
        open_body.extend_from_slice(session);
        let open = manual_case4(0x80, 0x10, &open_body);
        let open_rsp = response(session, 0, &[]);
        assert_eq!(bytes(&fields, &format!("{prefix}_open_request_hex")), open);
        assert_eq!(
            bytes(&fields, &format!("{prefix}_open_response_hex")),
            open_rsp
        );
        match parse_command(Media::ContactT1, &open).unwrap() {
            CommandRef::OpenSession {
                mode: actual,
                session_id,
            } => {
                assert_eq!(actual, mode);
                assert_eq!(session_id, session);
            }
            _ => panic!("wrong OPEN command"),
        }
        match parse_response(Instruction::OpenSession, &open_rsp).unwrap() {
            ResponseRef::OpenSession { envelope } => assert_envelope(envelope, session, 0),
            _ => panic!("wrong OPEN response"),
        }
    }

    let mut begin_body = vec![1];
    begin_body.extend_from_slice(&nonce);
    let begin = request(0x20, &SETUP_SESSION, 1, &begin_body);
    let begin_rsp = response(&SETUP_SESSION, 1, &[]);
    assert_eq!(bytes(&fields, "setup_begin_request_hex"), begin);
    assert_eq!(bytes(&fields, "setup_begin_response_hex"), begin_rsp);
    match parse_command(Media::ContactT1, &begin).unwrap() {
        CommandRef::BeginProvision {
            envelope,
            ordinal,
            provisioning_nonce,
        } => {
            assert_envelope(envelope, &SETUP_SESSION, 1);
            assert_eq!(ordinal, 1);
            assert_eq!(provisioning_nonce, nonce.as_slice());
        }
        _ => panic!("wrong BEGIN command"),
    }
    match parse_response(Instruction::BeginProvision, &begin_rsp).unwrap() {
        ResponseRef::BeginProvision { envelope } => assert_envelope(envelope, &SETUP_SESSION, 1),
        _ => panic!("wrong BEGIN response"),
    }

    for (step, offset) in [0u16, 192, 384, 576, 768].into_iter().enumerate() {
        let end = usize::min(usize::from(offset) + 192, record.len());
        let mut body = offset.to_be_bytes().to_vec();
        body.extend_from_slice(&record[usize::from(offset)..end]);
        let sequence = u32::try_from(step).unwrap() + 2;
        let command = request(0x21, &SETUP_SESSION, sequence, &body);
        let next = u16::try_from(end).unwrap();
        let rsp = response(&SETUP_SESSION, sequence, &next.to_be_bytes());
        assert_eq!(
            bytes(&fields, &format!("setup_write_{offset}_request_hex")),
            command
        );
        assert_eq!(
            bytes(&fields, &format!("setup_write_{offset}_response_hex")),
            rsp
        );
        match parse_command(Media::ContactT1, &command).unwrap() {
            CommandRef::WriteChunk {
                envelope,
                offset: actual,
                bytes: chunk,
            } => {
                assert_envelope(envelope, &SETUP_SESSION, sequence);
                assert_eq!(actual, offset);
                assert_eq!(chunk, &record[usize::from(offset)..end]);
            }
            _ => panic!("wrong WRITE command"),
        }
        match parse_response(Instruction::WriteChunk, &rsp).unwrap() {
            ResponseRef::WriteChunk {
                envelope,
                next_offset,
            } => {
                assert_envelope(envelope, &SETUP_SESSION, sequence);
                assert_eq!(next_offset, next);
            }
            _ => panic!("wrong WRITE response"),
        }
    }

    let commit = request(0x22, &SETUP_SESSION, 7, &[]);
    let commit_rsp = response(&SETUP_SESSION, 7, &[]);
    assert_eq!(bytes(&fields, "setup_commit_request_hex"), commit);
    assert_eq!(bytes(&fields, "setup_commit_response_hex"), commit_rsp);
    match parse_command(Media::ContactT1, &commit).unwrap() {
        CommandRef::Commit { envelope } => assert_envelope(envelope, &SETUP_SESSION, 7),
        _ => panic!("wrong COMMIT command"),
    }
    match parse_response(Instruction::Commit, &commit_rsp).unwrap() {
        ResponseRef::Commit { envelope } => assert_envelope(envelope, &SETUP_SESSION, 7),
        _ => panic!("wrong COMMIT response"),
    }

    let info = request(0x11, &NORMAL_SESSION, 1, &[]);
    let mut info_body = vec![1, 1, 2, 1, 2];
    info_body.extend_from_slice(&instance);
    info_body.extend_from_slice(&wallet);
    info_body.extend_from_slice(&fingerprint);
    info_body.extend_from_slice(&xpub);
    info_body.extend_from_slice(&0x000fu16.to_be_bytes());
    let info_rsp = response(&NORMAL_SESSION, 1, &info_body);
    assert_eq!(bytes(&fields, "normal_info_request_hex"), info);
    assert_eq!(bytes(&fields, "normal_info_response_hex"), info_rsp);
    match parse_command(Media::ContactT1, &info).unwrap() {
        CommandRef::GetInfo { envelope } => assert_envelope(envelope, &NORMAL_SESSION, 1),
        _ => panic!("wrong INFO command"),
    }
    match parse_response(Instruction::GetInfo, &info_rsp).unwrap() {
        ResponseRef::GetInfo {
            envelope,
            record_version,
            lifecycle,
            profile,
            role,
            instance_id,
            wallet_id,
            origin_fingerprint,
            account_xpub,
            allowed_operations,
        } => {
            assert_envelope(envelope, &NORMAL_SESSION, 1);
            assert_eq!((record_version, lifecycle, profile, role), (1, 2, 1, 2));
            assert_eq!(instance_id, instance.as_slice());
            assert_eq!(wallet_id, wallet.as_slice());
            assert_eq!(origin_fingerprint, fingerprint.as_slice());
            assert_eq!(account_xpub, xpub.as_slice());
            assert_eq!(allowed_operations, 0x000f);
        }
        _ => panic!("wrong INFO response"),
    }

    for (step, selector, offset, descriptor) in [
        (
            2,
            DescriptorSelector::Receive,
            0u16,
            fields["receive_descriptor"].as_bytes(),
        ),
        (
            3,
            DescriptorSelector::Receive,
            192,
            fields["receive_descriptor"].as_bytes(),
        ),
        (
            4,
            DescriptorSelector::Change,
            0,
            fields["change_descriptor"].as_bytes(),
        ),
        (
            5,
            DescriptorSelector::Change,
            192,
            fields["change_descriptor"].as_bytes(),
        ),
    ] {
        let end = usize::min(usize::from(offset) + 192, descriptor.len());
        let body = [
            selector.byte(),
            offset.to_be_bytes()[0],
            offset.to_be_bytes()[1],
        ];
        let command = request(0x12, &NORMAL_SESSION, step, &body);
        let mut rsp_body = body.to_vec();
        rsp_body.extend_from_slice(&descriptor[usize::from(offset)..end]);
        let rsp = response(&NORMAL_SESSION, step, &rsp_body);
        let label = format!("normal_read_{}_{offset}", selector.byte());
        assert_eq!(bytes(&fields, &format!("{label}_request_hex")), command);
        assert_eq!(bytes(&fields, &format!("{label}_response_hex")), rsp);
        match parse_command(Media::ContactT1, &command).unwrap() {
            CommandRef::ReadDChunk {
                envelope,
                selector: actual,
                offset: actual_offset,
            } => {
                assert_envelope(envelope, &NORMAL_SESSION, step);
                assert_eq!((actual, actual_offset), (selector, offset));
            }
            _ => panic!("wrong READ command"),
        }
        match parse_response(Instruction::ReadDChunk, &rsp).unwrap() {
            ResponseRef::ReadDChunk {
                envelope,
                selector: actual,
                offset: actual_offset,
                bytes: chunk,
            } => {
                assert_envelope(envelope, &NORMAL_SESSION, step);
                assert_eq!((actual, actual_offset), (selector, offset));
                assert_eq!(chunk, &descriptor[usize::from(offset)..end]);
            }
            _ => panic!("wrong READ response"),
        }
    }

    let a2_command = request(0x13, &NORMAL_SESSION, 6, &[2]);
    let mut a2_body = vec![2];
    a2_body.extend_from_slice(&a2);
    let a2_rsp = response(&NORMAL_SESSION, 6, &a2_body);
    assert_eq!(bytes(&fields, "normal_a2_request_hex"), a2_command);
    assert_eq!(bytes(&fields, "normal_a2_response_hex"), a2_rsp);
    match parse_command(Media::ContactT1, &a2_command).unwrap() {
        CommandRef::ExportA2 { envelope, purpose } => {
            assert_envelope(envelope, &NORMAL_SESSION, 6);
            assert_eq!(purpose, A2Purpose::Normal);
        }
        _ => panic!("wrong A2 command"),
    }
    match parse_response(Instruction::ExportA2, &a2_rsp).unwrap() {
        ResponseRef::ExportA2 {
            envelope,
            purpose,
            a2: actual,
        } => {
            assert_envelope(envelope, &NORMAL_SESSION, 6);
            assert_eq!(purpose, A2Purpose::Normal);
            assert_eq!(actual, a2.as_slice());
        }
        _ => panic!("wrong A2 response"),
    }

    let mut sign_body = wallet.clone();
    sign_body.extend_from_slice(&review);
    sign_body.extend_from_slice(&0u32.to_be_bytes());
    sign_body.push(0);
    sign_body.extend_from_slice(&0u32.to_be_bytes());
    sign_body.extend_from_slice(&digest);
    let sign = request(0x15, &NORMAL_SESSION, 7, &sign_body);
    let mut sign_rsp_body = review.clone();
    sign_rsp_body.extend_from_slice(&0u32.to_be_bytes());
    sign_rsp_body.extend_from_slice(&public_key);
    sign_rsp_body.push(u8::try_from(signature.len()).unwrap());
    sign_rsp_body.extend_from_slice(&signature);
    let sign_rsp = response(&NORMAL_SESSION, 7, &sign_rsp_body);
    assert_eq!(bytes(&fields, "normal_sign_0_request_hex"), sign);
    assert_eq!(bytes(&fields, "normal_sign_0_response_hex"), sign_rsp);
    match parse_command(Media::ContactT1, &sign).unwrap() {
        CommandRef::SignDigest {
            envelope,
            wallet_id,
            review_hash,
            input_index,
            branch,
            child_index,
            digest: actual,
        } => {
            assert_envelope(envelope, &NORMAL_SESSION, 7);
            assert_eq!(wallet_id, wallet.as_slice());
            assert_eq!(review_hash, review.as_slice());
            assert_eq!((input_index, branch, child_index), (0, 0, 0));
            assert_eq!(actual, digest.as_slice());
        }
        _ => panic!("wrong SIGN command"),
    }
    match parse_response(Instruction::SignDigest, &sign_rsp).unwrap() {
        ResponseRef::SignDigest {
            envelope,
            review_hash,
            input_index,
            public_key: actual_key,
            signature_der,
        } => {
            assert_envelope(envelope, &NORMAL_SESSION, 7);
            assert_eq!(review_hash, review.as_slice());
            assert_eq!(input_index, 0);
            assert_eq!(actual_key, public_key.as_slice());
            assert_eq!(signature_der, signature);
        }
        _ => panic!("wrong SIGN response"),
    }
}
