#![allow(clippy::panic, clippy::unwrap_used)]

use qk_device_wire::{
    encode_frame, parse_body, parse_frame, Artifact, BodyRef, Capability, CardRequestBody,
    CardResponseBody, DeviceError, DisplayBody, InputBody, MessageKind, NormalStage, OutputBody,
    Profile, RecipientOwnership, ReviewBody, Route, Source, HEADER_BYTES, MAGIC, MAX_BODY_BYTES,
    MAX_CARD_APDU_REQUEST_BODY_BYTES, MAX_CARD_APDU_RESPONSE_BODY_BYTES,
    MAX_CARD_FACTOR_BODY_BYTES, MAX_CHUNK_BODY_BYTES, MAX_DISPLAY_BODY_BYTES, MAX_FRAME_BYTES,
    MAX_KEYPAD_BODY_BYTES, MAX_OUTPUT_BEGIN_BODY_BYTES, VERSION,
};

fn raw_frame(capability: u8, kind: u8, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; HEADER_BYTES + body.len()];
    frame[..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = capability;
    frame[6] = kind;
    frame[7] = 0;
    frame[8..12].copy_from_slice(&sequence.to_le_bytes());
    frame[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
    frame[16..].copy_from_slice(body);
    frame
}

fn encoded(capability: Capability, kind: MessageKind, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut output = vec![0xa5; HEADER_BYTES + body.len() + 9];
    let length = encode_frame(capability, kind, sequence, body, &mut output).unwrap();
    assert_eq!(&output[length..], &[0xa5; 9]);
    output.truncate(length);
    output
}

fn assert_parse_error(capability: Capability, bytes: &[u8], expected: DeviceError) {
    match parse_frame(capability, bytes) {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("expected {expected}"),
    }
}

fn normal_factor(count: u16) -> Vec<u8> {
    let mut body = vec![0x11; 789];
    body[787..789].copy_from_slice(&count.to_le_bytes());
    for index in 0..count {
        body.extend_from_slice(&u32::from(index).to_le_bytes());
        body.extend_from_slice(&[0x02; 33]);
        body.push(8);
        body.extend_from_slice(&[0x30; 8]);
    }
    body
}

fn simple_bbqr_result() -> Vec<u8> {
    let mut body = vec![0x01, 0x02, 0x01];
    body.push(Artifact::FinalizedPsbt.wire_value());
    body.extend_from_slice(&7u32.to_le_bytes());
    body.extend_from_slice(&[0x22; 32]);
    body.extend_from_slice(&[0x33; 32]);
    body.extend_from_slice(&[0x44; 32]);
    body
}

#[test]
fn constants_and_capability_values_are_exact() {
    assert_eq!(MAGIC, *b"QKDV");
    assert_eq!(VERSION, 1);
    assert_eq!(HEADER_BYTES, 16);
    assert_eq!(MAX_BODY_BYTES, 2_097_152);
    assert_eq!(MAX_FRAME_BYTES, 2_097_168);
    assert_eq!(MAX_DISPLAY_BODY_BYTES, 180);
    assert_eq!(MAX_KEYPAD_BODY_BYTES, 17);
    assert_eq!(MAX_CARD_FACTOR_BODY_BYTES, 11_790);
    assert_eq!(MAX_CARD_APDU_REQUEST_BODY_BYTES, 221);
    assert_eq!(MAX_CARD_APDU_RESPONSE_BODY_BYTES, 218);
    assert_eq!(MAX_CHUNK_BODY_BYTES, 262_153);
    assert_eq!(MAX_OUTPUT_BEGIN_BODY_BYTES, 73);
    let values = [
        Capability::Display,
        Capability::Keypad,
        Capability::CardResponse,
        Capability::CardRequest,
        Capability::CameraInput,
        Capability::MediaInput,
        Capability::PrintOutput,
        Capability::MediaOutput,
    ]
    .map(Capability::wire_value);
    assert_eq!(values, [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn every_message_kind_preallocation_cap_is_exact() {
    let caps = [
        (MessageKind::DisplayStage, 1),
        (MessageKind::DisplayProfile, 1),
        (MessageKind::DisplayReview, 180),
        (MessageKind::DisplayResult, 180),
        (MessageKind::KeypadEvent, 17),
        (MessageKind::CardProfile, 1),
        (MessageKind::CardNormalFactor, 11_790),
        (MessageKind::CardApduResponse, 218),
        (MessageKind::CardRejected, 3),
        (MessageKind::CardReadProfile, 0),
        (MessageKind::CardReadNormalFactor, 0),
        (MessageKind::CardApduRequest, 221),
        (MessageKind::CameraBegin, 5),
        (MessageKind::CameraChunk, 262_153),
        (MessageKind::MediaReadBegin, 71),
        (MessageKind::MediaReadChunk, 262_153),
        (MessageKind::MediaBeginAccepted, 5),
        (MessageKind::MediaChunkAccepted, 4),
        (MessageKind::MediaFinished, 5),
        (MessageKind::MediaRejected, 3),
        (MessageKind::PrintWriteBegin, 73),
        (MessageKind::PrintWriteChunk, 262_153),
        (MessageKind::PrintWriteFinish, 5),
        (MessageKind::MediaWriteBegin, 73),
        (MessageKind::MediaWriteChunk, 262_153),
        (MessageKind::MediaWriteFinish, 5),
    ];
    for (kind, expected) in caps {
        assert_eq!(kind.body_cap(), expected, "{}", kind.wire_value());
    }
}

#[test]
fn card_apdu_qkdv_bodies_are_borrowed_and_bounded() {
    let request_body = [0x80, 0x20, 0x00, 0x00, 0x00];
    let request = encoded(
        Capability::CardRequest,
        MessageKind::CardApduRequest,
        1,
        &request_body,
    );
    match parse_frame(Capability::CardRequest, &request)
        .unwrap()
        .parsed_body()
        .unwrap()
    {
        BodyRef::CardApduRequest(body) => assert_eq!(body, request_body),
        _ => panic!("wrong request body"),
    }

    let response_body = [0x01, 0x90, 0x00];
    let response = encoded(
        Capability::CardResponse,
        MessageKind::CardApduResponse,
        1,
        &response_body,
    );
    match parse_frame(Capability::CardResponse, &response)
        .unwrap()
        .parsed_body()
        .unwrap()
    {
        BodyRef::CardApduResponse(body) => assert_eq!(body, response_body),
        _ => panic!("wrong response body"),
    }

    assert_parse_error(
        Capability::CardRequest,
        &raw_frame(4, 3, 1, &[0; 222]),
        DeviceError::BodyLengthExceeded,
    );
    assert_parse_error(
        Capability::CardResponse,
        &raw_frame(3, 0x83, 1, &[0; 219]),
        DeviceError::BodyLengthExceeded,
    );
}

#[test]
fn canonical_header_round_trip_and_output_atomicity() {
    let frame = encoded(
        Capability::Display,
        MessageKind::DisplayStage,
        0x7856_3412,
        &[0x01],
    );
    assert_eq!(&frame[..4], b"QKDV");
    assert_eq!(&frame[4..8], &[1, 1, 1, 0]);
    assert_eq!(&frame[8..12], &0x7856_3412u32.to_le_bytes());
    assert_eq!(&frame[12..16], &1u32.to_le_bytes());
    let parsed = parse_frame(Capability::Display, &frame).unwrap();
    assert_eq!(parsed.header().capability(), Capability::Display);
    assert_eq!(parsed.header().kind(), MessageKind::DisplayStage);
    assert_eq!(parsed.header().sequence(), 0x7856_3412);
    assert_eq!(parsed.body(), &[1]);

    let mut too_small = [0x77; 16];
    assert_eq!(
        encode_frame(
            Capability::Display,
            MessageKind::DisplayStage,
            1,
            &[1],
            &mut too_small,
        ),
        Err(DeviceError::OutputBufferTooSmall)
    );
    assert_eq!(too_small, [0x77; 16]);
}

#[test]
fn header_and_complete_frame_precedence_is_exact() {
    assert_parse_error(Capability::Display, &[0; 15], DeviceError::HeaderTruncated);
    let mut frame = raw_frame(1, 1, 1, &[1]);
    frame[0] ^= 1;
    frame[4] = 0xff;
    assert_parse_error(Capability::Display, &frame, DeviceError::MagicMismatch);
    frame[0] ^= 1;
    assert_parse_error(Capability::Display, &frame, DeviceError::VersionMismatch);
    frame[4] = 1;
    frame[5] = 9;
    assert_parse_error(
        Capability::Display,
        &frame,
        DeviceError::CapabilityOutOfRange,
    );
    frame[5] = 2;
    assert_parse_error(Capability::Display, &frame, DeviceError::CapabilityMismatch);
    frame[5] = 1;
    frame[6] = 0;
    assert_parse_error(Capability::Display, &frame, DeviceError::KindOutOfRange);
    frame[6] = 0x81;
    assert_parse_error(
        Capability::Display,
        &frame,
        DeviceError::CapabilityKindMismatch,
    );
    frame[6] = 1;
    frame[7] = 1;
    frame[8..12].fill(0);
    assert_parse_error(Capability::Display, &frame, DeviceError::ReservedNonZero);
    frame[7] = 0;
    assert_parse_error(Capability::Display, &frame, DeviceError::SequenceZero);
    frame[8..12].copy_from_slice(&1u32.to_le_bytes());
    frame[12..16].copy_from_slice(&2u32.to_le_bytes());
    assert_parse_error(Capability::Display, &frame, DeviceError::BodyLengthExceeded);
    frame[12..16].copy_from_slice(&1u32.to_le_bytes());
    frame.pop();
    assert_parse_error(Capability::Display, &frame, DeviceError::BodyTruncated);
    frame.push(1);
    frame.push(0);
    assert_parse_error(Capability::Display, &frame, DeviceError::TrailingByte);
}

#[test]
fn global_kind_universe_precedes_capability_membership() {
    for value in [0x00, 0x05, 0x80, 0x84, 0xfe] {
        assert_parse_error(
            Capability::Display,
            &raw_frame(1, value, 1, &[]),
            DeviceError::KindOutOfRange,
        );
    }
    for value in [0x81, 0x82, 0x83, 0xff] {
        assert_parse_error(
            Capability::Display,
            &raw_frame(1, value, 1, &[]),
            DeviceError::CapabilityKindMismatch,
        );
    }
}

#[test]
fn display_stage_profile_review_and_result_bodies_are_typed() {
    let stage = encoded(
        Capability::Display,
        MessageKind::DisplayStage,
        1,
        &[NormalStage::CompletedWiped.wire_value()],
    );
    assert!(matches!(
        parse_frame(Capability::Display, &stage)
            .unwrap()
            .parsed_body()
            .unwrap(),
        BodyRef::Display(DisplayBody::Stage(NormalStage::CompletedWiped))
    ));
    let profile = encoded(
        Capability::Display,
        MessageKind::DisplayProfile,
        1,
        &[Profile::QuantumShelter.wire_value()],
    );
    assert!(matches!(
        parse_frame(Capability::Display, &profile)
            .unwrap()
            .parsed_body()
            .unwrap(),
        BodyRef::Display(DisplayBody::Profile(Profile::QuantumShelter))
    ));

    let mut overview = vec![0x01, 0x02, 0x01];
    overview.extend_from_slice(&[0x55; 32]);
    overview.extend_from_slice(&3u32.to_le_bytes());
    overview.extend_from_slice(&99u64.to_le_bytes());
    let frame = encoded(
        Capability::Display,
        MessageKind::DisplayReview,
        1,
        &overview,
    );
    match parse_body(&parse_frame(Capability::Display, &frame).unwrap()).unwrap() {
        BodyRef::Display(DisplayBody::Review(ReviewBody::Overview {
            profile,
            input_count,
            total_input,
            ..
        })) => {
            assert_eq!(profile, Profile::Inheritance);
            assert_eq!(input_count, 3);
            assert_eq!(total_input, 99);
        }
        _ => panic!("wrong overview shape"),
    }

    let result = encoded(
        Capability::Display,
        MessageKind::DisplayResult,
        1,
        &simple_bbqr_result(),
    );
    match parse_frame(Capability::Display, &result)
        .unwrap()
        .parsed_body()
        .unwrap()
    {
        BodyRef::Display(DisplayBody::Result(result)) => {
            assert_eq!(result.profile(), Profile::SimpleRecovery);
            assert_eq!(result.route(), Route::Bbqr);
            assert_eq!(result.presence_bitmap(), 1);
            assert_eq!(result.finalized_psbt().unwrap().serialized_len(), 7);
            assert!(result.raw_transaction().is_none());
        }
        _ => panic!("wrong result shape"),
    }
}

#[test]
fn every_review_subtype_parses_and_nested_lengths_fail_closed() {
    let fixed = [
        vec![0x02; 1 + 24],
        vec![0x06, 1, 0, 0, 0],
        vec![0x07, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1],
        [vec![0x08], b"QK-FEE-POLICY-V2".to_vec()].concat(),
        vec![0x09; 1 + 20],
        vec![0x0a, 1],
        [vec![0x0b, 1], vec![0x66; 32]].concat(),
    ];
    for body in fixed {
        let frame = encoded(Capability::Display, MessageKind::DisplayReview, 1, &body);
        assert!(matches!(
            parse_frame(Capability::Display, &frame)
                .unwrap()
                .parsed_body(),
            Ok(BodyRef::Display(DisplayBody::Review(_)))
        ));
    }

    let mut recipient = vec![0x03];
    recipient.extend_from_slice(&0u32.to_le_bytes());
    recipient.extend_from_slice(&5u64.to_le_bytes());
    recipient.extend_from_slice(&22u16.to_le_bytes());
    recipient.extend_from_slice(&[0x00, 0x14]);
    recipient.extend_from_slice(&[0x77; 20]);
    recipient.extend_from_slice(&[0x01, 0x01]);
    recipient.extend_from_slice(&20u16.to_le_bytes());
    recipient.extend_from_slice(&[0x77; 20]);
    let frame = encoded(
        Capability::Display,
        MessageKind::DisplayReview,
        1,
        &recipient,
    );
    match parse_frame(Capability::Display, &frame)
        .unwrap()
        .parsed_body()
        .unwrap()
    {
        BodyRef::Display(DisplayBody::Review(ReviewBody::Recipient {
            ownership: RecipientOwnership::External { data, .. },
            ..
        })) => assert_eq!(data, &[0x77; 20]),
        _ => panic!("wrong recipient shape"),
    }
    let mut malformed = recipient;
    let last = malformed.len() - 1;
    malformed.truncate(last);
    let raw = raw_frame(1, 3, 1, &malformed);
    assert_parse_error(Capability::Display, &raw, DeviceError::NestedLengthMismatch);

    let mut change = vec![0x04];
    change.extend_from_slice(&0u32.to_le_bytes());
    change.extend_from_slice(&1u64.to_le_bytes());
    change.extend_from_slice(&34u16.to_le_bytes());
    change.extend_from_slice(&[0; 34]);
    change.extend_from_slice(&4u32.to_le_bytes());
    encoded(Capability::Display, MessageKind::DisplayReview, 1, &change);

    let mut op_return = vec![0x05];
    op_return.extend_from_slice(&0u32.to_le_bytes());
    op_return.extend_from_slice(&0u64.to_le_bytes());
    op_return.extend_from_slice(&2u16.to_le_bytes());
    op_return.extend_from_slice(&[0x6a, 0]);
    op_return.extend_from_slice(&0u16.to_le_bytes());
    encoded(
        Capability::Display,
        MessageKind::DisplayReview,
        1,
        &op_return,
    );
}

#[test]
fn keypad_card_input_output_and_reply_bodies_are_exact() {
    let keypad_cases: &[&[u8]] = &[
        &[1, 0x13],
        &[2, 3],
        &[3],
        &[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        &[5, 60, 0],
        &[6],
        &[7],
    ];
    assert_eq!(
        keypad_cases
            .iter()
            .map(|body| body.len())
            .collect::<Vec<_>>(),
        [2, 2, 1, 17, 3, 1, 1]
    );
    for body in keypad_cases {
        let frame = encoded(Capability::Keypad, MessageKind::KeypadEvent, 1, body);
        assert!(matches!(
            parse_frame(Capability::Keypad, &frame)
                .unwrap()
                .parsed_body(),
            Ok(BodyRef::Keypad(_))
        ));
    }
    assert_parse_error(
        Capability::Keypad,
        &raw_frame(2, 1, 1, &[5, 61, 0]),
        DeviceError::ValueOutOfRange,
    );

    for (kind, expected) in [
        (MessageKind::CardReadProfile, CardRequestBody::ReadProfile),
        (
            MessageKind::CardReadNormalFactor,
            CardRequestBody::ReadNormalFactor,
        ),
    ] {
        let frame = encoded(Capability::CardRequest, kind, 1, &[]);
        assert!(matches!(
            parse_frame(Capability::CardRequest, &frame)
                .unwrap()
                .parsed_body()
                .unwrap(),
            BodyRef::CardRequest(actual) if actual == expected
        ));
    }

    let factor = normal_factor(2);
    let frame = encoded(
        Capability::CardResponse,
        MessageKind::CardNormalFactor,
        1,
        &factor,
    );
    match parse_frame(Capability::CardResponse, &frame)
        .unwrap()
        .parsed_body()
        .unwrap()
    {
        BodyRef::CardResponse(CardResponseBody::NormalFactor(factor)) => {
            assert_eq!(factor.signature_count(), 2);
            assert_eq!(factor.signatures().len(), 2);
            assert_eq!(factor.signatures().next().unwrap().input_index(), 0);
        }
        _ => panic!("wrong factor shape"),
    }

    let camera_begin = [1, 67, 0, 0, 0];
    let frame = encoded(
        Capability::CameraInput,
        MessageKind::CameraBegin,
        1,
        &camera_begin,
    );
    assert!(matches!(
        frame_body(Capability::CameraInput, &frame),
        BodyRef::CameraInput(InputBody::Begin {
            source: Source::CameraA1Candidate,
            total_len: 67,
            ..
        })
    ));

    let camera_kit_begin = [2, 142, 0, 0, 0];
    let frame = encoded(
        Capability::CameraInput,
        MessageKind::CameraBegin,
        1,
        &camera_kit_begin,
    );
    assert!(matches!(
        frame_body(Capability::CameraInput, &frame),
        BodyRef::CameraInput(InputBody::Begin {
            source: Source::CameraKitCandidate,
            total_len: 142,
            ..
        })
    ));

    let filename = b"input.psbt";
    let mut media_begin = vec![4];
    media_begin.extend_from_slice(&25u32.to_le_bytes());
    media_begin.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    media_begin.extend_from_slice(filename);
    let frame = encoded(
        Capability::MediaInput,
        MessageKind::MediaReadBegin,
        1,
        &media_begin,
    );
    assert!(matches!(
        frame_body(Capability::MediaInput, &frame),
        BodyRef::MediaInput(InputBody::Begin {
            source: Source::MediaPsbt,
            filename: Some(b"input.psbt"),
            ..
        })
    ));

    let mut output_begin = vec![2];
    output_begin.extend_from_slice(&25u32.to_le_bytes());
    let output_name = b"qk-00000000000000000000000000000000-final.tx";
    output_begin.extend_from_slice(&(output_name.len() as u16).to_le_bytes());
    output_begin.extend_from_slice(output_name);
    let frame = encoded(
        Capability::MediaOutput,
        MessageKind::MediaWriteBegin,
        1,
        &output_begin,
    );
    assert!(matches!(
        frame_body(Capability::MediaOutput, &frame),
        BodyRef::MediaOutput(OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            ..
        })
    ));

    for (kind, body) in [
        (MessageKind::MediaBeginAccepted, vec![2, 25, 0, 0, 0]),
        (MessageKind::MediaChunkAccepted, vec![25, 0, 0, 0]),
        (MessageKind::MediaFinished, vec![2, 25, 0, 0, 0]),
        (MessageKind::MediaRejected, vec![3, 0x21, 0]),
    ] {
        let frame = encoded(Capability::MediaInput, kind, 1, &body);
        assert!(matches!(
            frame_body(Capability::MediaInput, &frame),
            BodyRef::OutputReply(_)
        ));
    }
}

fn frame_body<'a>(capability: Capability, frame: &'a [u8]) -> BodyRef<'a> {
    parse_frame(capability, frame)
        .unwrap()
        .parsed_body()
        .unwrap()
}

#[test]
fn factor_count_index_der_and_cap_errors_are_distinct() {
    let mut too_many = normal_factor(0);
    too_many[787..789].copy_from_slice(&101u16.to_le_bytes());
    assert_parse_error(
        Capability::CardResponse,
        &raw_frame(3, 0x82, 1, &too_many),
        DeviceError::CountExceeded,
    );

    let mut unordered = normal_factor(2);
    let second_index = 789 + 46;
    unordered[second_index..second_index + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_parse_error(
        Capability::CardResponse,
        &raw_frame(3, 0x82, 1, &unordered),
        DeviceError::IndexOrderMismatch,
    );

    let mut short_der = normal_factor(1);
    short_der[789 + 37] = 7;
    short_der.pop();
    assert_parse_error(
        Capability::CardResponse,
        &raw_frame(3, 0x82, 1, &short_der),
        DeviceError::ValueOutOfRange,
    );

    let over_cap = vec![0; MAX_CARD_FACTOR_BODY_BYTES + 1];
    assert_parse_error(
        Capability::CardResponse,
        &raw_frame(3, 0x82, 1, &over_cap),
        DeviceError::BodyLengthExceeded,
    );
}

#[test]
fn chunk_and_filename_rejections_are_named() {
    let zero_chunk = [0u8; 9];
    assert_parse_error(
        Capability::CameraInput,
        &raw_frame(5, 2, 1, &zero_chunk),
        DeviceError::ChunkLengthZero,
    );
    let mut bad_final = vec![0; 10];
    bad_final[4..8].copy_from_slice(&1u32.to_le_bytes());
    bad_final[8] = 2;
    assert_parse_error(
        Capability::CameraInput,
        &raw_frame(5, 2, 1, &bad_final),
        DeviceError::FinalFlagOutOfRange,
    );
    let mut bad_name = vec![4];
    bad_name.extend_from_slice(&1u32.to_le_bytes());
    bad_name.extend_from_slice(&6u16.to_le_bytes());
    bad_name.extend_from_slice(b"A.psbt");
    assert_parse_error(
        Capability::MediaInput,
        &raw_frame(6, 1, 1, &bad_name),
        DeviceError::FilenameRejected,
    );

    for total_len in [141u32, 143] {
        let mut kit = vec![Source::CameraKitCandidate.wire_value()];
        kit.extend_from_slice(&total_len.to_le_bytes());
        assert_parse_error(
            Capability::CameraInput,
            &raw_frame(5, 1, 1, &kit),
            DeviceError::SourceMismatch,
        );
    }

    let mut empty_output_name = vec![Artifact::RawTransaction.wire_value()];
    empty_output_name.extend_from_slice(&1u32.to_le_bytes());
    empty_output_name.extend_from_slice(&0u16.to_le_bytes());
    assert_parse_error(
        Capability::MediaOutput,
        &raw_frame(8, 1, 1, &empty_output_name),
        DeviceError::FilenameRejected,
    );
}

#[test]
fn output_reply_lengths_and_offsets_are_bounded() {
    for kind in [MessageKind::MediaBeginAccepted, MessageKind::MediaFinished] {
        for total_len in [0u32, 2_097_153] {
            let mut body = vec![Artifact::RawTransaction.wire_value()];
            body.extend_from_slice(&total_len.to_le_bytes());
            assert_parse_error(
                Capability::MediaInput,
                &raw_frame(6, kind.wire_value(), 1, &body),
                DeviceError::ValueOutOfRange,
            );
        }
    }

    for next_offset in [0u32, 2_097_153] {
        assert_parse_error(
            Capability::MediaInput,
            &raw_frame(
                6,
                MessageKind::MediaChunkAccepted.wire_value(),
                1,
                &next_offset.to_le_bytes(),
            ),
            DeviceError::ValueOutOfRange,
        );
    }

    for artifact in [Artifact::A1PrintArtifact, Artifact::KitPrintArtifact] {
        let mut body = vec![artifact.wire_value()];
        body.extend_from_slice(&1u32.to_le_bytes());
        let frame = encoded(
            Capability::MediaInput,
            MessageKind::MediaBeginAccepted,
            1,
            &body,
        );
        assert!(matches!(
            frame_body(Capability::MediaInput, &frame),
            BodyRef::OutputReply(_)
        ));
    }

    let mut unsupported = vec![Artifact::WatchOnlyBsms.wire_value()];
    unsupported.extend_from_slice(&1u32.to_le_bytes());
    assert_parse_error(
        Capability::MediaInput,
        &raw_frame(
            6,
            MessageKind::MediaBeginAccepted.wire_value(),
            1,
            &unsupported,
        ),
        DeviceError::ArtifactMismatch,
    );
}
