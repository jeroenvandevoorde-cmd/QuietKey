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
}

#[test]
fn media_exchange_echoes_begin_chunk_and_finish() {
    let mut exchange =
        ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput).unwrap();
    let begin = exchange.begin(MessageKind::MediaWriteBegin).unwrap();
    assert_eq!(begin.sequence(), 1);
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaBeginAccepted,
        1,
        &[2, 3, 0, 0, 0],
    );
    exchange.accept_response(&reply).unwrap();

    let chunk = exchange.begin(MessageKind::MediaWriteChunk).unwrap();
    assert_eq!(chunk.sequence(), 2);
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaChunkAccepted,
        1,
        &[3, 0, 0, 0],
    );
    // A new response descriptor owner would start at one for a new process;
    // the exchange identity itself remains the authoritative echo check.
    assert_eq!(
        exchange.accept_response(&reply),
        Err(DeviceError::ResponseSequenceMismatch)
    );
}

#[test]
fn input_transfer_enforces_offset_final_and_completion() {
    let mut transfer = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source: Source::CameraA1Candidate,
            total_len: 3,
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
            chunk: &[3],
        })
        .unwrap();
    transfer.finish().unwrap();

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
}

#[test]
fn output_transfer_requires_exact_artifact_length_and_finish() {
    let mut transfer = OutputTransfer::begin(
        Capability::MediaOutput,
        OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"",
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

    let mut incomplete = OutputTransfer::begin(
        Capability::MediaOutput,
        OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: 3,
            filename: b"",
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
            filename: b"",
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
