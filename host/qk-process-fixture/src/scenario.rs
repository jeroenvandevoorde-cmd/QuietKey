//! Test-only driver for the registered public Normal fixture.
//!
//! PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL. The two source fixture
//! files are included from their frozen locations and are never copied here.

use crate::common::{CycleSpec, FixtureError, Ingress, Negative, Profile, Route};
use crate::wipe::{bytes as wipe_bytes, WipingVec};
use qk_bbqr::{encode_typed_frame, encoded_part_count, BbqrFileType, MAX_FRAME_TEXT_BYTES};
use qk_device_wire::{
    Artifact, BodyRef, Capability, CardRequestBody, DirectRbf, DisplayBody, MessageKind, Network,
    NormalStage, OneWayProtocol, OutputBody, OutputTransfer, Profile as WireProfile,
    RecipientOwnership, RecipientType, ResultBody, ReviewBody, Route as WireRoute, Source,
    StreamDecoder, Warning, HEADER_BYTES, MAX_CHUNK_BYTES,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const SIGNING: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");

const DISPLAY_FD: i32 = 3;
const KEYPAD_FD: i32 = 4;
const CARD_RESPONSE_FD: i32 = 5;
const CARD_REQUEST_FD: i32 = 6;
const CAMERA_FD: i32 = 7;
const MEDIA_INPUT_FD: i32 = 8;
const PRINT_OUTPUT_FD: i32 = 9;
const MEDIA_OUTPUT_FD: i32 = 10;
const INPUT_FILENAME: &[u8] = b"normal-v2.psbt";
const BBQR_PART_BYTES: usize = 60;
const EXPORT_PART_BYTES: u16 = 60;
const EXPORT_NONCE: [u8; 16] = [0x51; 16];
const REVIEW_COUNT: usize = 13;
// Canonical schema-v3 review hash for the registered S0 with InputSource::Qr.
// A byte-only constructor changed only byte 2 of the registered 682-byte
// `canonical_review_v3_hex` from MicroSd 01 to Qr 02, then computed SHA-256
// over `QuietKey/D-09/review/v3 || 00 || canonical_review`; that result agrees
// with the typed qk-core path. The MicroSd sibling remains read from the
// frozen fixture file below.
const QR_REVIEW_HASH: [u8; 32] = [
    0xc4, 0x22, 0x24, 0xff, 0x0d, 0xf8, 0x50, 0xcd, 0x75, 0x38, 0x9a, 0x1a, 0x4b, 0x4c, 0x49, 0x6d,
    0x8a, 0x39, 0x9c, 0xf5, 0xe8, 0xe4, 0x60, 0x8d, 0x40, 0xf4, 0xe3, 0xf5, 0x68, 0x0d, 0x6e, 0x0f,
];

pub fn run_driver(spec: CycleSpec) -> Result<(), FixtureError> {
    preload_inputs(spec)?;

    let mut card_requests = open_fd(CARD_REQUEST_FD, true)?;
    let mut card_responses = open_fd(CARD_RESPONSE_FD, false)?;
    let mut request_decoder = StreamDecoder::new(Capability::CardRequest);
    let mut response_protocol = OneWayProtocol::new(Capability::CardResponse);

    let profile_request = read_frame(&mut card_requests, &mut request_decoder)?;
    if !matches!(
        profile_request
            .parsed_body()
            .map_err(|_| FixtureError::Wire)?,
        BodyRef::CardRequest(CardRequestBody::ReadProfile)
    ) {
        return Err(FixtureError::FactMismatch);
    }
    let served_profile = if spec.negative == Some(Negative::ProfileMismatch) {
        match spec.profile {
            Profile::SimpleRecovery => Profile::Inheritance,
            Profile::Inheritance | Profile::QuantumShelter => Profile::SimpleRecovery,
        }
    } else {
        spec.profile
    };
    write_protocol_frame(
        &mut card_responses,
        &mut response_protocol,
        MessageKind::CardProfile,
        &[served_profile.wire()],
    )?;
    if spec.negative == Some(Negative::ProfileMismatch) {
        return Ok(());
    }

    let factor_request = read_frame(&mut card_requests, &mut request_decoder)?;
    if !matches!(
        factor_request
            .parsed_body()
            .map_err(|_| FixtureError::Wire)?,
        BodyRef::CardRequest(CardRequestBody::ReadNormalFactor)
    ) {
        return Err(FixtureError::FactMismatch);
    }
    let factor = normal_factor(spec.negative)?;
    write_protocol_frame(
        &mut card_responses,
        &mut response_protocol,
        MessageKind::CardNormalFactor,
        factor.as_slice(),
    )?;

    let mut display = open_fd(DISPLAY_FD, true)?;
    let mut keypad = open_fd(KEYPAD_FD, false)?;
    let mut display_decoder = StreamDecoder::new(Capability::Display);
    let mut keypad_protocol = OneWayProtocol::new(Capability::Keypad);
    let mut review_index = 0usize;
    let mut saw_result = false;
    let mut saw_start = false;

    loop {
        let frame = match read_frame(&mut display, &mut display_decoder) {
            Ok(frame) => frame,
            Err(FixtureError::UnexpectedEof) if spec.negative.is_some() => return Ok(()),
            Err(error) => return Err(error),
        };
        let body = frame.parsed_body().map_err(|_| FixtureError::Wire)?;
        match body {
            BodyRef::Display(DisplayBody::Stage(stage)) => match stage {
                NormalStage::NormalStart => saw_start = true,
                NormalStage::Transport => {
                    if !saw_start {
                        return Err(FixtureError::FactMismatch);
                    }
                    let source = match spec.ingress {
                        Ingress::Camera => Source::CameraBbqrPsbt,
                        Ingress::Media => Source::MediaPsbt,
                    };
                    write_keypad(
                        &mut keypad,
                        &mut keypad_protocol,
                        &[0x02, source.wire_value()],
                    )?;
                }
                NormalStage::AwaitingExportAction => {
                    let mut event = [0u8; 17];
                    let event_len = match spec.route {
                        Route::Sd => {
                            event[0] = 0x04;
                            event[1..].copy_from_slice(&EXPORT_NONCE);
                            event.len()
                        }
                        Route::Bbqr => {
                            event[0] = 0x05;
                            event[1..3].copy_from_slice(&EXPORT_PART_BYTES.to_le_bytes());
                            3
                        }
                    };
                    write_keypad(
                        &mut keypad,
                        &mut keypad_protocol,
                        event.get(..event_len).ok_or(FixtureError::Fixture)?,
                    )?;
                    wipe_bytes(&mut event);
                }
                NormalStage::CompletedWiped => {
                    if spec.negative.is_some() || review_index != REVIEW_COUNT || !saw_result {
                        return Err(FixtureError::FactMismatch);
                    }
                    verify_device_outputs(spec)?;
                    return Ok(());
                }
                _ => {}
            },
            BodyRef::Display(DisplayBody::Profile(profile)) => {
                if profile != wire_profile(spec.profile) {
                    return Err(FixtureError::FactMismatch);
                }
                if spec.negative == Some(Negative::EarlyHold) {
                    write_keypad(&mut keypad, &mut keypad_protocol, &[0x03])?;
                } else {
                    write_keypad(&mut keypad, &mut keypad_protocol, &[0x01, 0x13])?;
                }
            }
            BodyRef::Display(DisplayBody::Review(review)) => {
                verify_review(review_index, review, spec.profile, spec.ingress)?;
                review_index = review_index
                    .checked_add(1)
                    .ok_or(FixtureError::FactMismatch)?;
                if matches!(review, ReviewBody::FinalApproval { .. }) {
                    write_keypad(&mut keypad, &mut keypad_protocol, &[0x03])?;
                } else {
                    write_keypad(&mut keypad, &mut keypad_protocol, &[0x01, 0x13])?;
                }
            }
            BodyRef::Display(DisplayBody::Result(result)) => {
                verify_result(result, spec)?;
                saw_result = true;
                write_keypad(&mut keypad, &mut keypad_protocol, &[0x01, 0x13])?;
            }
            _ => return Err(FixtureError::FactMismatch),
        }
    }
}

fn preload_inputs(spec: CycleSpec) -> Result<(), FixtureError> {
    match spec.negative {
        Some(Negative::HostileQkdv) => {
            let mut camera = open_fd(CAMERA_FD, false)?;
            let mut hostile = [0u8; HEADER_BYTES];
            hostile[0..4].copy_from_slice(b"BAD!");
            hostile[4] = 1;
            hostile[5] = Capability::CameraInput.wire_value();
            hostile[6] = MessageKind::CameraBegin.wire_value();
            hostile[8..12].copy_from_slice(&1u32.to_le_bytes());
            hostile[12..16].copy_from_slice(&5u32.to_le_bytes());
            camera.write_all(&hostile).map_err(|_| FixtureError::Io)?;
            wipe_bytes(&mut hostile);
            return Ok(());
        }
        Some(Negative::IngressCap) => {
            let mut camera = open_fd(CAMERA_FD, false)?;
            let body = [Source::CameraBbqrPsbt.wire_value(), 0x01, 0x00, 0x20, 0x00];
            let mut frame = [0u8; HEADER_BYTES + 5];
            frame[0..4].copy_from_slice(b"QKDV");
            frame[4] = 1;
            frame[5] = Capability::CameraInput.wire_value();
            frame[6] = MessageKind::CameraBegin.wire_value();
            frame[8..12].copy_from_slice(&1u32.to_le_bytes());
            frame[12..16].copy_from_slice(&5u32.to_le_bytes());
            frame[16..].copy_from_slice(&body);
            camera.write_all(&frame).map_err(|_| FixtureError::Io)?;
            wipe_bytes(&mut frame);
            return Ok(());
        }
        _ => {}
    }

    let signing = hex_field(SIGNING, "s0_hex")?;
    let a1 = hex_field(PROVISIONING, "a1_capsule_hex")?;
    match spec.ingress {
        Ingress::Camera => {
            let record = bbqr_record(signing.as_slice())?;
            let mut camera = open_fd(CAMERA_FD, false)?;
            let mut protocol = OneWayProtocol::new(Capability::CameraInput);
            send_input(
                &mut camera,
                &mut protocol,
                Capability::CameraInput,
                Source::CameraBbqrPsbt,
                None,
                record.as_slice(),
            )?;
            send_input(
                &mut camera,
                &mut protocol,
                Capability::CameraInput,
                Source::CameraA1Candidate,
                None,
                a1.as_slice(),
            )?;
        }
        Ingress::Media => {
            let mut media = open_fd(MEDIA_INPUT_FD, false)?;
            let mut media_protocol = OneWayProtocol::new(Capability::MediaInput);
            send_input(
                &mut media,
                &mut media_protocol,
                Capability::MediaInput,
                Source::MediaPsbt,
                Some(INPUT_FILENAME),
                signing.as_slice(),
            )?;
            let mut camera = open_fd(CAMERA_FD, false)?;
            let mut camera_protocol = OneWayProtocol::new(Capability::CameraInput);
            send_input(
                &mut camera,
                &mut camera_protocol,
                Capability::CameraInput,
                Source::CameraA1Candidate,
                None,
                a1.as_slice(),
            )?;
        }
    }
    Ok(())
}

fn send_input(
    writer: &mut File,
    protocol: &mut OneWayProtocol,
    capability: Capability,
    source: Source,
    filename: Option<&[u8]>,
    payload: &[u8],
) -> Result<(), FixtureError> {
    let total_len = u32::try_from(payload.len()).map_err(|_| FixtureError::Fixture)?;
    let mut begin = WipingVec::zeroed(if let Some(name) = filename {
        7usize
            .checked_add(name.len())
            .ok_or(FixtureError::Fixture)?
    } else {
        5
    })
    .map_err(|_| FixtureError::Fixture)?;
    begin.as_mut_slice()[0] = source.wire_value();
    begin.as_mut_slice()[1..5].copy_from_slice(&total_len.to_le_bytes());
    let begin_kind = if let Some(name) = filename {
        begin.as_mut_slice()[5..7].copy_from_slice(
            &u16::try_from(name.len())
                .map_err(|_| FixtureError::Fixture)?
                .to_le_bytes(),
        );
        begin.as_mut_slice()[7..].copy_from_slice(name);
        MessageKind::MediaReadBegin
    } else {
        MessageKind::CameraBegin
    };
    write_protocol_frame(writer, protocol, begin_kind, begin.as_slice())?;

    for (index, chunk) in payload.chunks(MAX_CHUNK_BYTES).enumerate() {
        let offset = index
            .checked_mul(MAX_CHUNK_BYTES)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(FixtureError::Fixture)?;
        let mut body = WipingVec::zeroed(
            9usize
                .checked_add(chunk.len())
                .ok_or(FixtureError::Fixture)?,
        )
        .map_err(|_| FixtureError::Fixture)?;
        body.as_mut_slice()[0..4].copy_from_slice(&offset.to_le_bytes());
        body.as_mut_slice()[4..8].copy_from_slice(
            &u32::try_from(chunk.len())
                .map_err(|_| FixtureError::Fixture)?
                .to_le_bytes(),
        );
        body.as_mut_slice()[8] = u8::from(
            usize::try_from(offset)
                .ok()
                .and_then(|value| value.checked_add(chunk.len()))
                == Some(payload.len()),
        );
        body.as_mut_slice()[9..].copy_from_slice(chunk);
        let kind = match capability {
            Capability::CameraInput => MessageKind::CameraChunk,
            Capability::MediaInput => MessageKind::MediaReadChunk,
            _ => return Err(FixtureError::Fixture),
        };
        write_protocol_frame(writer, protocol, kind, body.as_slice())?;
    }
    Ok(())
}

fn bbqr_record(payload: &[u8]) -> Result<WipingVec, FixtureError> {
    let count =
        encoded_part_count(payload.len(), BBQR_PART_BYTES).map_err(|_| FixtureError::Fixture)?;
    let mut frames = Vec::with_capacity(usize::from(count));
    for index in 0..count {
        let mut frame = [0u8; MAX_FRAME_TEXT_BYTES];
        let length = encode_typed_frame(
            BbqrFileType::Psbt,
            payload,
            BBQR_PART_BYTES,
            index,
            &mut frame,
        )
        .map_err(|_| FixtureError::Fixture)?;
        let copied = WipingVec::from_slice(frame.get(..length).ok_or(FixtureError::Fixture)?)
            .map_err(|_| FixtureError::Fixture)?;
        wipe_bytes(&mut frame);
        frames.push(copied);
    }
    let mut record = WipingVec::zeroed(0).map_err(|_| FixtureError::Fixture)?;
    record
        .extend(&count.to_le_bytes())
        .map_err(|_| FixtureError::Fixture)?;
    for frame in frames.iter().rev() {
        record
            .extend(
                &u16::try_from(frame.len())
                    .map_err(|_| FixtureError::Fixture)?
                    .to_le_bytes(),
            )
            .map_err(|_| FixtureError::Fixture)?;
        record
            .extend(frame.as_slice())
            .map_err(|_| FixtureError::Fixture)?;
    }
    Ok(record)
}

fn normal_factor(negative: Option<Negative>) -> Result<WipingVec, FixtureError> {
    let receive = field(PROVISIONING, "receive_descriptor")?.as_bytes();
    let change = field(PROVISIONING, "change_descriptor")?.as_bytes();
    if receive.len() != 306 || change.len() != 306 {
        return Err(FixtureError::Fixture);
    }
    let mut wallet_id = hex_field(PROVISIONING, "wallet_id")?;
    let xpub = field(PROVISIONING, "role_b_account_xpub")?.as_bytes();
    let a2 = hex_field(PROVISIONING, "a2_transcript_sha256")?;
    let mut public_key = hex_field(SIGNING, "role_b_route_public_key_hex")?;
    let original_der = hex_field(SIGNING, "role_b_der_hex")?;
    let der = if negative == Some(Negative::HighS) {
        high_s_der(original_der.as_slice())?
    } else {
        WipingVec::from_slice(original_der.as_slice()).map_err(|_| FixtureError::Fixture)?
    };
    if negative == Some(Negative::WrongWallet) {
        wallet_id.as_mut_slice()[0] ^= 1;
    }
    if negative == Some(Negative::WrongKey) {
        public_key.as_mut_slice()[32] ^= 1;
    }
    if wallet_id.len() != 32 || xpub.len() != 111 || a2.len() != 32 || public_key.len() != 33 {
        return Err(FixtureError::Fixture);
    }
    let length = 789usize
        .checked_add(38)
        .and_then(|value| value.checked_add(der.len()))
        .ok_or(FixtureError::Fixture)?;
    let mut body = WipingVec::zeroed(length).map_err(|_| FixtureError::Fixture)?;
    let mut offset = 0usize;
    append(body.as_mut_slice(), &mut offset, receive)?;
    append(body.as_mut_slice(), &mut offset, change)?;
    append(body.as_mut_slice(), &mut offset, wallet_id.as_slice())?;
    append(body.as_mut_slice(), &mut offset, xpub)?;
    append(body.as_mut_slice(), &mut offset, a2.as_slice())?;
    append(body.as_mut_slice(), &mut offset, &1u16.to_le_bytes())?;
    append(body.as_mut_slice(), &mut offset, &0u32.to_le_bytes())?;
    append(body.as_mut_slice(), &mut offset, public_key.as_slice())?;
    append(
        body.as_mut_slice(),
        &mut offset,
        &[u8::try_from(der.len()).map_err(|_| FixtureError::Fixture)?],
    )?;
    append(body.as_mut_slice(), &mut offset, der.as_slice())?;
    if offset != body.len() {
        return Err(FixtureError::Fixture);
    }
    Ok(body)
}

fn high_s_der(low: &[u8]) -> Result<WipingVec, FixtureError> {
    if low.len() != 71 || low.get(0..4) != Some(&[0x30, 0x45, 0x02, 0x21]) {
        return Err(FixtureError::Fixture);
    }
    let mut high = WipingVec::zeroed(72).map_err(|_| FixtureError::Fixture)?;
    high.as_mut_slice()[0..4].copy_from_slice(&[0x30, 0x46, 0x02, 0x21]);
    high.as_mut_slice()[4..37].copy_from_slice(&low[4..37]);
    high.as_mut_slice()[37..40].copy_from_slice(&[0x02, 0x21, 0x00]);
    high.as_mut_slice()[40] = 0x80;
    high.as_mut_slice()[71] = 0x01;
    Ok(high)
}

fn verify_review(
    index: usize,
    review: ReviewBody<'_>,
    profile: Profile,
    ingress: Ingress,
) -> Result<(), FixtureError> {
    let wallet_id = hex_field(PROVISIONING, "wallet_id")?;
    let review_hash = hex_field(SIGNING, "review_hash_hex")?;
    let change_script = hex_field(PROVISIONING, "change_0_script_pubkey")?;
    let self_program = hex_field(
        "self_program: 2fe9bb02255457981f0613c8f7b5cc2f354fade42a4b4b19f22b3566e1c6bae0\n",
        "self_program",
    )?;
    let matches = match (index, review) {
        (
            0,
            ReviewBody::Overview {
                profile: actual,
                network: Network::BitcoinMainnet,
                wallet_id: actual_wallet,
                input_count: 1,
                total_input: 1_000_000,
            },
        ) => actual == wire_profile(profile) && actual_wallet == wallet_id.as_slice(),
        (
            1,
            ReviewBody::Arithmetic {
                total_input: 1_000_000,
                total_output: 900_000,
                fee: 100_000,
            },
        ) => true,
        (
            2,
            ReviewBody::Recipient {
                output_index: 1,
                amount: 300_000,
                script,
                ownership:
                    RecipientOwnership::SelfTransfer {
                        child_index: 1,
                        witness_program,
                    },
            },
        ) => {
            script.len() == 34
                && script.get(..2) == Some(&[0, 32])
                && script.get(2..) == Some(self_program.as_slice())
                && witness_program == self_program.as_slice()
        }
        (
            3,
            ReviewBody::Recipient {
                output_index: 2,
                amount: 200_000,
                script,
                ownership:
                    RecipientOwnership::External {
                        recipient_type: RecipientType::P2wpkh,
                        data,
                    },
            },
        ) => {
            script
                == [0x00, 0x14]
                    .into_iter()
                    .chain([0x11; 20])
                    .collect::<Vec<_>>()
                && data == [0x11; 20]
        }
        (
            4,
            ReviewBody::Change {
                output_index: 0,
                amount: 400_000,
                script,
                child_index: 0,
            },
        ) => script == change_script.as_slice(),
        (
            5,
            ReviewBody::OpReturn {
                output_index: 3,
                amount: 0,
                script,
                payload,
            },
        ) => script == [0x6a, 0x03, 0xaa, 0xbb, 0xcc] && payload == [0xaa, 0xbb, 0xcc],
        (6, ReviewBody::Locktime { locktime: 500_000 }) => true,
        (
            7,
            ReviewBody::Sequence {
                input_index: 0,
                sequence: 0xffff_fffd,
                direct_rbf: DirectRbf::Signaled,
            },
        ) => true,
        (8, ReviewBody::FeePolicy) => true,
        (
            9,
            ReviewBody::FeeFacts {
                fee: 100_000,
                estimated_vsize: 238,
                fee_rate_msat_per_vbyte: 420_168,
            },
        ) => true,
        (10, ReviewBody::Warning(Warning::FeeRateHigh)) => true,
        (11, ReviewBody::Warning(Warning::FeeShareHigh)) => true,
        (
            12,
            ReviewBody::FinalApproval {
                profile: actual,
                review_hash: actual_hash,
            },
        ) => {
            let expected_hash = match ingress {
                Ingress::Camera => QR_REVIEW_HASH.as_slice(),
                Ingress::Media => review_hash.as_slice(),
            };
            actual == wire_profile(profile) && actual_hash == expected_hash
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(FixtureError::FactMismatch)
    }
}

fn verify_result(result: ResultBody<'_>, spec: CycleSpec) -> Result<(), FixtureError> {
    if result.profile() != wire_profile(spec.profile)
        || result.route()
            != match spec.route {
                Route::Sd => WireRoute::Sd,
                Route::Bbqr => WireRoute::Bbqr,
            }
    {
        return Err(FixtureError::FactMismatch);
    }
    let finalized_len = decimal_field(SIGNING, "finalized_psbt_len")?;
    let raw_len = decimal_field(SIGNING, "raw_transaction_len")?;
    let finalized_hash = hex_field(SIGNING, "finalized_psbt_sha256")?;
    let raw_hash = hex_field(SIGNING, "raw_transaction_sha256")?;
    let txid = hex_field(SIGNING, "txid_raw_hex")?;
    let wtxid = hex_field(SIGNING, "wtxid_raw_hex")?;
    if result.txid() != txid.as_slice() || result.wtxid() != wtxid.as_slice() {
        return Err(FixtureError::FactMismatch);
    }
    let (want_psbt, want_raw, want_psbt_receipt, want_raw_receipt, bitmap) =
        match (spec.profile, spec.route) {
            (Profile::SimpleRecovery | Profile::Inheritance, Route::Sd) => {
                (true, true, true, true, 0x0f)
            }
            (Profile::SimpleRecovery | Profile::Inheritance, Route::Bbqr) => {
                (true, false, false, false, 0x01)
            }
            (Profile::QuantumShelter, Route::Sd) => (false, true, false, true, 0x0a),
            (Profile::QuantumShelter, Route::Bbqr) => (false, true, false, false, 0x02),
        };
    if result.presence_bitmap() != bitmap
        || result.finalized_psbt().is_some() != want_psbt
        || result.raw_transaction().is_some() != want_raw
        || result.finalized_psbt_receipt().is_some() != want_psbt_receipt
        || result.raw_transaction_receipt().is_some() != want_raw_receipt
    {
        return Err(FixtureError::FactMismatch);
    }
    if let Some(fact) = result.finalized_psbt() {
        if fact.kind() != Artifact::FinalizedPsbt
            || u64::from(fact.serialized_len()) != finalized_len
            || fact.sha256() != finalized_hash.as_slice()
        {
            return Err(FixtureError::FactMismatch);
        }
    }
    if let Some(fact) = result.raw_transaction() {
        if fact.kind() != Artifact::RawTransaction
            || u64::from(fact.serialized_len()) != raw_len
            || fact.sha256() != raw_hash.as_slice()
        {
            return Err(FixtureError::FactMismatch);
        }
    }
    if result.finalized_psbt_receipt().is_some_and(|receipt| {
        receipt.kind() != Artifact::FinalizedPsbt || u64::from(receipt.total_len()) != finalized_len
    }) || result.raw_transaction_receipt().is_some_and(|receipt| {
        receipt.kind() != Artifact::RawTransaction || u64::from(receipt.total_len()) != raw_len
    }) {
        return Err(FixtureError::FactMismatch);
    }
    Ok(())
}

fn verify_device_outputs(spec: CycleSpec) -> Result<(), FixtureError> {
    let mut print_output = open_fd(PRINT_OUTPUT_FD, true)?;
    if spec.route == Route::Sd {
        let mut media_output = open_fd(MEDIA_OUTPUT_FD, true)?;
        let mut decoder = StreamDecoder::new(Capability::MediaOutput);
        match spec.profile {
            Profile::SimpleRecovery | Profile::Inheritance => {
                let expected = hex_field(SIGNING, "finalized_psbt_hex")?;
                collect_output(
                    &mut media_output,
                    &mut decoder,
                    Artifact::FinalizedPsbt,
                    expected.as_slice(),
                )?;
                let expected = hex_field(SIGNING, "raw_transaction_hex")?;
                collect_output(
                    &mut media_output,
                    &mut decoder,
                    Artifact::RawTransaction,
                    expected.as_slice(),
                )?;
            }
            Profile::QuantumShelter => {
                let expected = hex_field(SIGNING, "raw_transaction_hex")?;
                collect_output(
                    &mut media_output,
                    &mut decoder,
                    Artifact::RawTransaction,
                    expected.as_slice(),
                )?;
            }
        }
        require_empty_eof(&mut media_output)?;
    } else {
        let mut media_output = open_fd(MEDIA_OUTPUT_FD, true)?;
        require_empty_eof(&mut media_output)?;
    }
    require_empty_eof(&mut print_output)
}

fn require_empty_eof(reader: &mut File) -> Result<(), FixtureError> {
    let mut byte = [0u8; 1];
    let received = reader.read(&mut byte).map_err(|_| FixtureError::Io)?;
    wipe_bytes(&mut byte);
    if received == 0 {
        Ok(())
    } else {
        Err(FixtureError::FactMismatch)
    }
}

fn collect_output(
    reader: &mut File,
    decoder: &mut StreamDecoder,
    expected_artifact: Artifact,
    expected: &[u8],
) -> Result<(), FixtureError> {
    let begin = read_frame(reader, decoder)?;
    let begin_body = match begin.parsed_body().map_err(|_| FixtureError::Wire)? {
        BodyRef::MediaOutput(body @ OutputBody::WriteBegin { .. }) => body,
        _ => return Err(FixtureError::FactMismatch),
    };
    let (artifact, total_len) = match begin_body {
        OutputBody::WriteBegin {
            artifact,
            total_len,
            filename,
        } if !filename.is_empty() => (artifact, total_len),
        _ => return Err(FixtureError::FactMismatch),
    };
    if artifact != expected_artifact || total_len as usize != expected.len() {
        return Err(FixtureError::FactMismatch);
    }
    let mut transfer = OutputTransfer::begin(Capability::MediaOutput, begin_body)
        .map_err(|_| FixtureError::Wire)?;
    let mut bytes = WipingVec::zeroed(expected.len()).map_err(|_| FixtureError::Fixture)?;
    loop {
        let frame = read_frame(reader, decoder)?;
        match frame.parsed_body().map_err(|_| FixtureError::Wire)? {
            BodyRef::MediaOutput(body @ OutputBody::WriteChunk { offset, chunk }) => {
                transfer.accept(body).map_err(|_| FixtureError::Wire)?;
                let start = usize::try_from(offset).map_err(|_| FixtureError::FactMismatch)?;
                let end = start
                    .checked_add(chunk.len())
                    .ok_or(FixtureError::FactMismatch)?;
                bytes
                    .as_mut_slice()
                    .get_mut(start..end)
                    .ok_or(FixtureError::FactMismatch)?
                    .copy_from_slice(chunk);
            }
            BodyRef::MediaOutput(
                body @ OutputBody::WriteFinish {
                    artifact,
                    total_len,
                },
            ) => {
                if artifact != expected_artifact || total_len as usize != expected.len() {
                    return Err(FixtureError::FactMismatch);
                }
                transfer.finish(body).map_err(|_| FixtureError::Wire)?;
                if bytes.as_slice() != expected {
                    return Err(FixtureError::FactMismatch);
                }
                return Ok(());
            }
            _ => return Err(FixtureError::FactMismatch),
        }
    }
}

fn write_keypad(
    writer: &mut File,
    protocol: &mut OneWayProtocol,
    body: &[u8],
) -> Result<(), FixtureError> {
    write_protocol_frame(writer, protocol, MessageKind::KeypadEvent, body)
}

fn write_protocol_frame(
    writer: &mut File,
    protocol: &mut OneWayProtocol,
    kind: MessageKind,
    body: &[u8],
) -> Result<(), FixtureError> {
    let length = HEADER_BYTES
        .checked_add(body.len())
        .ok_or(FixtureError::Fixture)?;
    let mut bytes = WipingVec::zeroed(length).map_err(|_| FixtureError::Fixture)?;
    let outbound = protocol.next(kind).map_err(|_| FixtureError::Wire)?;
    let written = outbound
        .encode(body, bytes.as_mut_slice())
        .map_err(|_| FixtureError::Wire)?;
    if written != length {
        return Err(FixtureError::Wire);
    }
    writer
        .write_all(bytes.as_slice())
        .map_err(|_| FixtureError::Io)
}

fn read_frame(
    reader: &mut File,
    decoder: &mut StreamDecoder,
) -> Result<qk_device_wire::ReceivedFrame, FixtureError> {
    let mut byte = [0u8; 1];
    loop {
        let received = reader.read(&mut byte).map_err(|_| FixtureError::Io)?;
        if received == 0 {
            let _ = decoder.finish();
            wipe_bytes(&mut byte);
            return Err(FixtureError::UnexpectedEof);
        }
        let outcome = decoder.ingest(&byte).map_err(|_| FixtureError::Wire)?;
        wipe_bytes(&mut byte);
        if outcome.frame_ready() {
            return decoder.take_frame().map_err(|_| FixtureError::Wire);
        }
    }
}

fn open_fd(descriptor: i32, read: bool) -> Result<File, FixtureError> {
    let mut options = OpenOptions::new();
    options.read(read).write(!read);
    options
        .open(format!("/dev/fd/{descriptor}"))
        .map_err(|_| FixtureError::Io)
}

fn wire_profile(profile: Profile) -> WireProfile {
    match profile {
        Profile::SimpleRecovery => WireProfile::SimpleRecovery,
        Profile::Inheritance => WireProfile::Inheritance,
        Profile::QuantumShelter => WireProfile::QuantumShelter,
    }
}

fn field<'a>(source: &'a str, name: &str) -> Result<&'a str, FixtureError> {
    source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(": "))
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .ok_or(FixtureError::Fixture)
}

fn decimal_field(source: &str, name: &str) -> Result<u64, FixtureError> {
    field(source, name)?
        .parse::<u64>()
        .map_err(|_| FixtureError::Fixture)
}

fn hex_field(source: &str, name: &str) -> Result<WipingVec, FixtureError> {
    let text = field(source, name)?;
    if !text.len().is_multiple_of(2) {
        return Err(FixtureError::Fixture);
    }
    let mut output = WipingVec::zeroed(text.len() / 2).map_err(|_| FixtureError::Fixture)?;
    for (target, pair) in output
        .as_mut_slice()
        .iter_mut()
        .zip(text.as_bytes().chunks(2))
    {
        *target = u8::from_str_radix(
            core::str::from_utf8(pair).map_err(|_| FixtureError::Fixture)?,
            16,
        )
        .map_err(|_| FixtureError::Fixture)?;
    }
    Ok(output)
}

fn append(output: &mut [u8], offset: &mut usize, value: &[u8]) -> Result<(), FixtureError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(FixtureError::Fixture)?;
    output
        .get_mut(*offset..end)
        .ok_or(FixtureError::Fixture)?
        .copy_from_slice(value);
    *offset = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_inputs_are_included_and_match_exact_widths() {
        assert_eq!(
            field(PROVISIONING, "receive_descriptor").unwrap().len(),
            306
        );
        assert_eq!(field(PROVISIONING, "change_descriptor").unwrap().len(), 306);
        assert_eq!(hex_field(PROVISIONING, "a1_capsule_hex").unwrap().len(), 67);
        assert_eq!(hex_field(SIGNING, "s0_hex").unwrap().len(), 730);
        assert_eq!(
            hex_field(SIGNING, "role_b_route_public_key_hex")
                .unwrap()
                .len(),
            33
        );
        assert_eq!(hex_field(SIGNING, "role_b_der_hex").unwrap().len(), 71);
    }

    #[test]
    fn normal_factor_variants_are_body_valid_and_named_precedence_inputs() {
        for negative in [None, Some(Negative::WrongWallet), Some(Negative::WrongKey)] {
            let factor = normal_factor(negative).unwrap();
            let mut frame = vec![0u8; HEADER_BYTES + factor.len()];
            qk_device_wire::encode_frame(
                Capability::CardResponse,
                MessageKind::CardNormalFactor,
                1,
                factor.as_slice(),
                &mut frame,
            )
            .unwrap();
        }
        let high = normal_factor(Some(Negative::HighS)).unwrap();
        let mut frame = vec![0u8; HEADER_BYTES + high.len()];
        qk_device_wire::encode_frame(
            Capability::CardResponse,
            MessageKind::CardNormalFactor,
            1,
            high.as_slice(),
            &mut frame,
        )
        .unwrap();
    }

    #[test]
    fn camera_bbqr_record_uses_registered_payload_without_copy_fixture() {
        let payload = hex_field(SIGNING, "s0_hex").unwrap();
        let record = bbqr_record(payload.as_slice()).unwrap();
        assert!(!record.as_slice().is_empty());
        assert_eq!(
            u16::from_le_bytes(record.as_slice()[0..2].try_into().unwrap()),
            13
        );
    }

    #[test]
    fn fd_topology_is_exact() {
        assert_eq!(
            [
                DISPLAY_FD,
                KEYPAD_FD,
                CARD_RESPONSE_FD,
                CARD_REQUEST_FD,
                CAMERA_FD,
                MEDIA_INPUT_FD,
                PRINT_OUTPUT_FD,
                MEDIA_OUTPUT_FD,
            ],
            [3, 4, 5, 6, 7, 8, 9, 10]
        );
    }
}
