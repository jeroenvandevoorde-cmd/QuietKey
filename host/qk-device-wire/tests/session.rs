#![allow(clippy::unwrap_used)]

use qk_device_wire::{
    encode_frame, Artifact, Capability, DeviceError, ExchangeProtocol, InputBody, InputTransfer,
    MessageKind, OneWayProtocol, OutputBody, OutputTransfer, ReceivedFrame, Source, StreamDecoder,
    HEADER_BYTES,
};

fn received(
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
    body: &[u8],
) -> ReceivedFrame {
    let mut bytes = vec![0; HEADER_BYTES + body.len()];
    encode_frame(capability, kind, sequence, body, &mut bytes).unwrap();
    let mut decoder = StreamDecoder::new(capability);
    decoder.ingest(&bytes).unwrap();
    decoder.take_frame().unwrap()
}

fn received_next(
    decoder: &mut StreamDecoder,
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
    body: &[u8],
) -> ReceivedFrame {
    let mut bytes = vec![0; HEADER_BYTES + body.len()];
    encode_frame(capability, kind, sequence, body, &mut bytes).unwrap();
    decoder.ingest(&bytes).unwrap();
    decoder.take_frame().unwrap()
}

#[test]
fn one_way_outbound_and_inbound_sequences_are_exact() {
    let mut outbound = OneWayProtocol::new(Capability::Display);
    assert_eq!(
        outbound.next(MessageKind::DisplayStage).unwrap().sequence(),
        1
    );
    assert_eq!(
        outbound
            .next(MessageKind::DisplayProfile)
            .unwrap()
            .sequence(),
        2
    );

    let mut mismatch = OneWayProtocol::new(Capability::Display);
    assert_eq!(
        mismatch.next(MessageKind::KeypadEvent),
        Err(DeviceError::CapabilityKindMismatch)
    );
    assert!(mismatch.is_terminated());

    let mut inbound = OneWayProtocol::new(Capability::Display);
    let frame = received(Capability::Display, MessageKind::DisplayStage, 1, &[1]);
    inbound.accept(&frame).unwrap();
}

#[test]
fn card_exchange_requires_one_matching_response() {
    let mut exchange =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    let request = exchange.begin(MessageKind::CardReadProfile).unwrap();
    assert_eq!(request.sequence(), 1);
    assert!(exchange.has_outstanding());
    assert_eq!(
        exchange.begin(MessageKind::CardReadNormalFactor),
        Err(DeviceError::OutstandingExchange)
    );
    assert!(exchange.is_terminated());

    let mut exchange =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    exchange.begin(MessageKind::CardReadProfile).unwrap();
    let response = received(Capability::CardResponse, MessageKind::CardProfile, 1, &[1]);
    exchange.accept_response(&response).unwrap();
    assert!(!exchange.has_outstanding());
    assert_eq!(
        exchange
            .begin(MessageKind::CardReadNormalFactor)
            .unwrap()
            .sequence(),
        2
    );
}

#[test]
fn raw_card_apdu_exchange_requires_kind_83_at_the_same_sequence() {
    let mut exchange =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    let request = exchange.begin(MessageKind::CardApduRequest).unwrap();
    assert_eq!(request.sequence(), 1);
    let response = received(
        Capability::CardResponse,
        MessageKind::CardApduResponse,
        1,
        &[0x90, 0x00],
    );
    exchange.accept_response(&response).unwrap();
    assert!(!exchange.has_outstanding());
}

#[test]
fn response_without_request_wrong_kind_and_device_rejection_terminate() {
    let profile = received(Capability::CardResponse, MessageKind::CardProfile, 1, &[1]);
    let mut absent =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    assert_eq!(
        absent.accept_response(&profile),
        Err(DeviceError::NoOutstandingExchange)
    );

    let mut wrong =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    wrong.begin(MessageKind::CardReadNormalFactor).unwrap();
    assert_eq!(
        wrong.accept_response(&profile),
        Err(DeviceError::ResponseKindMismatch)
    );

    let rejected = received(
        Capability::CardResponse,
        MessageKind::CardRejected,
        1,
        &[1, 1, 0],
    );
    let mut device =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    device.begin(MessageKind::CardReadProfile).unwrap();
    assert_eq!(
        device.accept_response(&rejected),
        Err(DeviceError::DeviceRejected)
    );
    assert!(!device.has_outstanding());
    assert!(device.is_terminated());
    assert_eq!(
        device.begin(MessageKind::CardReadNormalFactor),
        Err(DeviceError::DecoderTerminated)
    );
}

#[test]
fn media_exchange_echoes_begin_chunk_and_finish() {
    let mut exchange =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    let mut replies = StreamDecoder::new(Capability::MediaInput);
    let begin = exchange
        .begin_output(OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"qk-00000000000000000000000000000000-final.tx",
        })
        .unwrap();
    assert_eq!(begin.sequence(), 1);
    let reply = received_next(
        &mut replies,
        Capability::MediaInput,
        MessageKind::MediaBeginAccepted,
        1,
        &[2, 3, 0, 0, 0],
    );
    assert_eq!(
        reply.header().kind().wire_value(),
        begin.kind().wire_value() | 0x80
    );
    exchange.accept_response(&reply).unwrap();

    let chunk = exchange
        .begin_output(OutputBody::WriteChunk {
            offset: 0,
            chunk: &[1, 2, 3],
        })
        .unwrap();
    assert_eq!(chunk.sequence(), 2);
    let reply = received_next(
        &mut replies,
        Capability::MediaInput,
        MessageKind::MediaChunkAccepted,
        2,
        &[3, 0, 0, 0],
    );
    assert_eq!(
        reply.header().kind().wire_value(),
        chunk.kind().wire_value() | 0x80
    );
    exchange.accept_response(&reply).unwrap();

    let finish = exchange
        .begin_output(OutputBody::WriteFinish {
            artifact: Artifact::RawTransaction,
            total_len: 3,
        })
        .unwrap();
    assert_eq!(finish.sequence(), 3);
    let reply = received_next(
        &mut replies,
        Capability::MediaInput,
        MessageKind::MediaFinished,
        3,
        &[2, 3, 0, 0, 0],
    );
    assert_eq!(
        reply.header().kind().wire_value(),
        finish.kind().wire_value() | 0x80
    );
    exchange.accept_response(&reply).unwrap();
    assert!(!exchange.has_outstanding());
}

#[test]
fn output_exchange_rejects_unbound_or_mismatched_echo_facts() {
    let mut unbound =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    assert_eq!(
        unbound.begin(MessageKind::MediaWriteBegin),
        Err(DeviceError::UnexpectedFrame)
    );

    let mut wrong_artifact =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    wrong_artifact
        .begin_output(OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"qk-00000000000000000000000000000000-final.tx",
        })
        .unwrap();
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaBeginAccepted,
        1,
        &[1, 3, 0, 0, 0],
    );
    assert_eq!(
        wrong_artifact.accept_response(&reply),
        Err(DeviceError::ArtifactMismatch)
    );

    let mut wrong_total =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    wrong_total
        .begin_output(OutputBody::WriteFinish {
            artifact: Artifact::RawTransaction,
            total_len: 3,
        })
        .unwrap();
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaFinished,
        1,
        &[2, 4, 0, 0, 0],
    );
    assert_eq!(
        wrong_total.accept_response(&reply),
        Err(DeviceError::ArtifactMismatch)
    );

    let mut wrong_offset =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    wrong_offset
        .begin_output(OutputBody::WriteChunk {
            offset: 7,
            chunk: &[1, 2, 3],
        })
        .unwrap();
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaChunkAccepted,
        1,
        &[9, 0, 0, 0],
    );
    assert_eq!(
        wrong_offset.accept_response(&reply),
        Err(DeviceError::OffsetMismatch)
    );
}

#[test]
fn print_exchange_accepts_only_the_exact_print_artifact_echo() {
    let mut exchange =
        ExchangeProtocol::new(Capability::PrintOutput, Capability::MediaInput).unwrap();
    exchange
        .begin_output(OutputBody::WriteBegin {
            artifact: Artifact::A1PrintArtifact,
            total_len: 67,
            filename: b"",
        })
        .unwrap();
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaBeginAccepted,
        1,
        &[4, 67, 0, 0, 0],
    );
    exchange.accept_response(&reply).unwrap();
}

#[test]
fn input_transfer_enforces_offset_final_and_completion() {
    let mut transfer = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source: Source::CameraA1Candidate,
            total_len: 67,
            filename: None,
        },
    )
    .unwrap();
    transfer
        .accept(InputBody::Chunk {
            offset: 0,
            final_chunk: false,
            chunk: &[1, 2],
        })
        .unwrap();
    assert_eq!(transfer.next_offset(), 2);
    transfer
        .accept(InputBody::Chunk {
            offset: 2,
            final_chunk: true,
            chunk: &[3; 65],
        })
        .unwrap();
    transfer.finish().unwrap();
    assert_eq!(transfer.finish(), Err(DeviceError::UnexpectedFrame));
    assert_eq!(transfer.finish(), Err(DeviceError::DecoderTerminated));

    let mut wrong_final = InputTransfer::begin(
        Capability::MediaInput,
        InputBody::Begin {
            source: Source::MediaPsbt,
            total_len: 2,
            filename: Some(b"a.psbt"),
        },
    )
    .unwrap();
    assert_eq!(
        wrong_final.accept(InputBody::Chunk {
            offset: 0,
            final_chunk: true,
            chunk: &[1],
        }),
        Err(DeviceError::FinalFlagMismatch)
    );

    let mut wrong_offset = InputTransfer::begin(
        Capability::MediaInput,
        InputBody::Begin {
            source: Source::MediaPsbt,
            total_len: 2,
            filename: Some(b"a.psbt"),
        },
    )
    .unwrap();
    assert_eq!(
        wrong_offset.accept(InputBody::Chunk {
            offset: 1,
            final_chunk: true,
            chunk: &[1],
        }),
        Err(DeviceError::OffsetMismatch)
    );

    let kit = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source: Source::CameraKitCandidate,
            total_len: 142,
            filename: None,
        },
    )
    .unwrap();
    assert_eq!(kit.source(), Source::CameraKitCandidate);

    for (source, total_len, expected) in [
        (Source::CameraA1Candidate, 66, DeviceError::SourceMismatch),
        (Source::CameraKitCandidate, 143, DeviceError::SourceMismatch),
        (Source::CameraBbqrPsbt, 0, DeviceError::SourceMismatch),
        (Source::MediaPsbt, 0, DeviceError::ValueOutOfRange),
    ] {
        let capability = if source == Source::MediaPsbt {
            Capability::MediaInput
        } else {
            Capability::CameraInput
        };
        let filename = if source == Source::MediaPsbt {
            Some(b"a.psbt".as_slice())
        } else {
            None
        };
        assert!(matches!(
            InputTransfer::begin(
                capability,
                InputBody::Begin {
                    source,
                    total_len,
                    filename,
                },
            ),
            Err(error) if error == expected
        ));
    }

    let mut empty = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source: Source::CameraBbqrPsbt,
            total_len: 1,
            filename: None,
        },
    )
    .unwrap();
    assert_eq!(
        empty.accept(InputBody::Chunk {
            offset: 0,
            final_chunk: false,
            chunk: &[],
        }),
        Err(DeviceError::ChunkLengthZero)
    );

    let mut oversized = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source: Source::CameraBbqrPsbt,
            total_len: 262_145,
            filename: None,
        },
    )
    .unwrap();
    let oversized_chunk = vec![0; 262_145];
    assert_eq!(
        oversized.accept(InputBody::Chunk {
            offset: 0,
            final_chunk: true,
            chunk: &oversized_chunk,
        }),
        Err(DeviceError::ChunkLengthExceeded)
    );
}

#[test]
fn bound_output_header_refuses_different_emitted_facts() {
    let mut exchange =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    let outbound = exchange
        .begin_output(OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"qk-00000000000000000000000000000000-final.tx",
        })
        .unwrap();
    let name = b"qk-00000000000000000000000000000000-final.psbt";
    let mut different = vec![Artifact::FinalizedPsbt.wire_value()];
    different.extend_from_slice(&4u32.to_le_bytes());
    different.extend_from_slice(&(name.len() as u16).to_le_bytes());
    different.extend_from_slice(name);
    let mut encoded = vec![0u8; HEADER_BYTES + different.len()];
    assert_eq!(
        outbound.encode(&different, &mut encoded),
        Err(DeviceError::ArtifactMismatch)
    );

    let mut exchange =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    let outbound = exchange
        .begin_output(OutputBody::WriteChunk {
            offset: 7,
            chunk: &[1, 2, 3],
        })
        .unwrap();
    let mut different = Vec::new();
    different.extend_from_slice(&8u32.to_le_bytes());
    different.extend_from_slice(&2u32.to_le_bytes());
    different.extend_from_slice(&[1, 2]);
    let mut encoded = vec![0u8; HEADER_BYTES + different.len()];
    assert_eq!(
        outbound.encode(&different, &mut encoded),
        Err(DeviceError::OffsetMismatch)
    );
}

#[test]
fn output_transfer_requires_exact_artifact_length_and_finish() {
    let mut transfer = OutputTransfer::begin(
        Capability::MediaOutput,
        OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"qk-00000000000000000000000000000000-final.tx",
        },
    )
    .unwrap();
    transfer
        .accept(OutputBody::WriteChunk {
            offset: 0,
            chunk: &[1, 2, 3],
        })
        .unwrap();
    transfer
        .finish(OutputBody::WriteFinish {
            artifact: Artifact::RawTransaction,
            total_len: 3,
        })
        .unwrap();
    assert_eq!(
        transfer.finish(OutputBody::WriteFinish {
            artifact: Artifact::RawTransaction,
            total_len: 3,
        }),
        Err(DeviceError::UnexpectedFrame)
    );
    assert_eq!(
        transfer.finish(OutputBody::WriteFinish {
            artifact: Artifact::RawTransaction,
            total_len: 3,
        }),
        Err(DeviceError::DecoderTerminated)
    );

    let mut incomplete = OutputTransfer::begin(
        Capability::MediaOutput,
        OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"qk-00000000000000000000000000000000-final.tx",
        },
    )
    .unwrap();
    assert_eq!(
        incomplete.finish(OutputBody::WriteFinish {
            artifact: Artifact::RawTransaction,
            total_len: 3,
        }),
        Err(DeviceError::TransferIncomplete)
    );

    let mut mismatch = OutputTransfer::begin(
        Capability::MediaOutput,
        OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 1,
            filename: b"qk-00000000000000000000000000000000-final.tx",
        },
    )
    .unwrap();
    mismatch
        .accept(OutputBody::WriteChunk {
            offset: 0,
            chunk: &[1],
        })
        .unwrap();
    assert_eq!(
        mismatch.finish(OutputBody::WriteFinish {
            artifact: Artifact::FinalizedPsbt,
            total_len: 1,
        }),
        Err(DeviceError::ArtifactMismatch)
    );
}

#[test]
fn unsupported_pairs_and_peer_loss_fail_closed() {
    assert!(matches!(
        ExchangeProtocol::new(Capability::Display, Capability::Keypad),
        Err(DeviceError::CapabilityMismatch)
    ));
    let mut exchange =
        ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse).unwrap();
    exchange.begin(MessageKind::CardReadProfile).unwrap();
    assert_eq!(exchange.peer_lost(), DeviceError::PeerLost);
    assert!(exchange.is_terminated());
}
