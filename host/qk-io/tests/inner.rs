use qk_io::{
    parse_request, Artifact, InnerError, Operation, Request, Sink, Source, INNER_HEADER_BYTES,
    INNER_VERSION, MAX_INNER_BODY_BYTES,
};

fn request(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    bytes.extend_from_slice(&[INNER_VERSION, opcode, 0, 0]);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn all_five_request_grammars_parse_byte_exactly() {
    let ingress_aux = [0u8; 0];
    let ingress = request(
        Operation::IngressBegin.wire_value(),
        &[Source::CameraKitCandidate.wire_value(), 0, 0],
    );
    match parse_request(&ingress).expect("ingress begin") {
        Request::IngressBegin { source, aux } => {
            assert_eq!(source, Source::CameraKitCandidate);
            assert_eq!(aux, ingress_aux);
        }
        _ => panic!("wrong request"),
    }

    let read = request(Operation::IngressRead.wire_value(), &17u32.to_le_bytes());
    match parse_request(&read).expect("ingress read") {
        Request::IngressRead { expected_offset } => assert_eq!(expected_offset, 17),
        _ => panic!("wrong request"),
    }

    let mut begin_body = vec![
        Sink::Bbqr.wire_value(),
        Artifact::RawTransaction.wire_value(),
    ];
    begin_body.extend_from_slice(&99u32.to_le_bytes());
    begin_body.extend_from_slice(&2u16.to_le_bytes());
    begin_body.extend_from_slice(&25u16.to_le_bytes());
    let begin = request(Operation::EgressBegin.wire_value(), &begin_body);
    match parse_request(&begin).expect("egress begin") {
        Request::EgressBegin {
            sink,
            artifact,
            total_len,
            aux,
        } => {
            assert_eq!(sink, Sink::Bbqr);
            assert_eq!(artifact, Artifact::RawTransaction);
            assert_eq!(total_len, 99);
            assert_eq!(aux, 25u16.to_le_bytes());
        }
        _ => panic!("wrong request"),
    }

    let mut write_body = Vec::new();
    write_body.extend_from_slice(&7u32.to_le_bytes());
    write_body.extend_from_slice(&3u32.to_le_bytes());
    write_body.extend_from_slice(b"abc");
    let write = request(Operation::EgressWrite.wire_value(), &write_body);
    match parse_request(&write).expect("egress write") {
        Request::EgressWrite { offset, chunk } => {
            assert_eq!(offset, 7);
            assert_eq!(chunk, b"abc");
        }
        _ => panic!("wrong request"),
    }

    let finish = request(Operation::EgressFinish.wire_value(), &[]);
    assert!(matches!(parse_request(&finish), Ok(Request::EgressFinish)));
}

#[test]
fn common_header_precedence_and_exact_body_boundary_are_closed() {
    assert!(matches!(
        parse_request(&[]),
        Err(InnerError::InnerHeaderTruncated)
    ));

    let mut bytes = request(Operation::EgressFinish.wire_value(), &[]);
    bytes[0] = 2;
    assert!(matches!(
        parse_request(&bytes),
        Err(InnerError::InnerVersionMismatch)
    ));
    bytes[0] = INNER_VERSION;
    bytes[2] = 1;
    assert!(matches!(
        parse_request(&bytes),
        Err(InnerError::RequestReservedNonZero)
    ));
    bytes[2] = 0;
    bytes[1] = 0xff;
    assert!(matches!(
        parse_request(&bytes),
        Err(InnerError::OperationOutOfRange)
    ));

    let mut oversized = request(Operation::EgressFinish.wire_value(), &[]);
    oversized[4..8].copy_from_slice(&((MAX_INNER_BODY_BYTES + 1) as u32).to_le_bytes());
    assert!(matches!(
        parse_request(&oversized),
        Err(InnerError::BodyLengthExceeded)
    ));

    let mut truncated = request(Operation::IngressRead.wire_value(), &[0; 4]);
    truncated.pop();
    assert!(matches!(
        parse_request(&truncated),
        Err(InnerError::BodyTruncated)
    ));

    let mut trailing = request(Operation::EgressFinish.wire_value(), &[]);
    trailing.push(0);
    assert!(matches!(
        parse_request(&trailing),
        Err(InnerError::TrailingByte)
    ));
}

#[test]
fn nested_tags_and_lengths_have_named_rejections() {
    let bad_source = request(Operation::IngressBegin.wire_value(), &[0, 0, 0]);
    assert!(matches!(
        parse_request(&bad_source),
        Err(InnerError::SourceOutOfRange)
    ));

    let bad_sink = request(
        Operation::EgressBegin.wire_value(),
        &[0, 1, 0, 0, 0, 0, 0, 0],
    );
    assert!(matches!(
        parse_request(&bad_sink),
        Err(InnerError::SinkOutOfRange)
    ));

    let bad_artifact = request(
        Operation::EgressBegin.wire_value(),
        &[1, 0, 0, 0, 0, 0, 0, 0],
    );
    assert!(matches!(
        parse_request(&bad_artifact),
        Err(InnerError::ArtifactOutOfRange)
    ));

    let short_nested = request(
        Operation::IngressBegin.wire_value(),
        &[Source::MediaPsbt.wire_value(), 2, 0, b'x'],
    );
    assert!(matches!(
        parse_request(&short_nested),
        Err(InnerError::BodyTruncated)
    ));

    let trailing_nested = request(
        Operation::IngressBegin.wire_value(),
        &[Source::MediaPsbt.wire_value(), 0, 0, b'x'],
    );
    assert!(matches!(
        parse_request(&trailing_nested),
        Err(InnerError::TrailingByte)
    ));
}

#[test]
fn every_local_status_is_nonzero_named_and_stable() {
    let errors = [
        InnerError::InnerHeaderTruncated,
        InnerError::InnerVersionMismatch,
        InnerError::RequestReservedNonZero,
        InnerError::OperationOutOfRange,
        InnerError::BodyLengthExceeded,
        InnerError::BodyTruncated,
        InnerError::TrailingByte,
        InnerError::UnexpectedBoundary,
        InnerError::BoundaryMissing,
        InnerError::SourceKindMismatch,
        InnerError::SourceAlreadyUsed,
        InnerError::WriterKindMismatch,
        InnerError::WriterAlreadyUsed,
        InnerError::ActiveTransfer,
        InnerError::NoActiveTransfer,
        InnerError::WrongTransferDirection,
        InnerError::SourceLengthMismatch,
        InnerError::DeclaredLengthZero,
        InnerError::DeclaredLengthExceeded,
        InnerError::OffsetMismatch,
        InnerError::ChunkLengthZero,
        InnerError::ChunkLengthExceeded,
        InnerError::TransferLengthExceeded,
        InnerError::TransferIncomplete,
        InnerError::SourceOutOfRange,
        InnerError::SinkOutOfRange,
        InnerError::ArtifactOutOfRange,
        InnerError::SinkArtifactMismatch,
        InnerError::InvalidFilename,
        InnerError::InvalidBbqrPartLength,
        InnerError::AllocationFailed,
        InnerError::SourceReadFailed,
        InnerError::OutputCollision,
        InnerError::OutputCreateFailed,
        InnerError::OutputWriteFailed,
        InnerError::OutputSyncFailed,
        InnerError::OutputCloseFailed,
        InnerError::OutputReopenFailed,
        InnerError::OutputReadbackMismatch,
        InnerError::OutputRenameFailed,
        InnerError::PrintFailed,
    ];
    for (index, error) in errors.into_iter().enumerate() {
        assert_eq!(error.status_code(), (index + 1) as u16);
        assert_eq!(error.to_string(), format!("{error:?}"));
    }
}

#[test]
fn bbqr_statuses_are_the_exact_contiguous_registered_range() {
    use qk_bbqr::BbqrError;
    let errors = [
        BbqrError::EmptyPayload,
        BbqrError::PayloadTooLarge,
        BbqrError::InvalidNonFinalPartLength,
        BbqrError::TooManyParts,
        BbqrError::PartIndexOutOfRange,
        BbqrError::FrameTooShort,
        BbqrError::FrameTooLarge,
        BbqrError::InvalidMagic,
        BbqrError::UnsupportedEncoding,
        BbqrError::UnsupportedFileType,
        BbqrError::InvalidDeclaredPartCount,
        BbqrError::DeclaredPartCountExceeded,
        BbqrError::InvalidPartIndex,
        BbqrError::EmptyPart,
        BbqrError::Base32PaddingForbidden,
        BbqrError::MalformedBase32Symbol,
        BbqrError::NonCanonicalBase32Length,
        BbqrError::NonCanonicalBase32Padding,
        BbqrError::NonFinalPartLengthNotMultipleOfFive,
        BbqrError::StreamEncodingMismatch,
        BbqrError::StreamFileTypeMismatch,
        BbqrError::StreamPartCountMismatch,
        BbqrError::NonUniformPartLength,
        BbqrError::FinalPartTooLarge,
        BbqrError::TotalDecodedSizeExceeded,
        BbqrError::ConflictingDuplicate,
        BbqrError::DuplicateWorkExceeded,
        BbqrError::SubmissionWorkExceeded,
        BbqrError::Incomplete,
        BbqrError::AlreadyComplete,
    ];
    for (index, error) in errors.into_iter().enumerate() {
        let wrapped = InnerError::Bbqr(error);
        assert_eq!(wrapped.status_code(), 0x0101 + index as u16);
        assert_eq!(wrapped.to_string(), error.to_string());
    }
}
