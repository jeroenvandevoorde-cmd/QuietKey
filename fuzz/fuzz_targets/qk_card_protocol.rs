#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_card_protocol::{
    allowed_operations, encode_open_session, encode_rejection, parse_command, parse_record,
    parse_response, reset_wiped_bytes, wiped_bytes, EncodeError, Instruction, Lifecycle, Media,
    Mode, ProtocolError, RecordError, ResponseError, StatusWord, MAX_REQUEST_BYTES,
};

const FIXTURE: &str =
    include_str!("../../host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

fn exact_fixture_line(data: &[u8]) -> Option<&str> {
    let line = core::str::from_utf8(data.strip_suffix(b"\n")?).ok()?;
    FIXTURE
        .lines()
        .any(|registered| registered == line)
        .then_some(line)
}

fn protocol_error_name(error: ProtocolError) -> &'static str {
    let name = match error {
        ProtocolError::WrongLength => "WrongLength",
        ProtocolError::IncorrectP1P2 => "IncorrectP1P2",
        ProtocolError::InstructionNotSupported => "InstructionNotSupported",
        ProtocolError::ClassNotSupported => "ClassNotSupported",
        ProtocolError::ProtocolVersionMismatch => "ProtocolVersionMismatch",
        ProtocolError::ContactInterfaceRequired => "ContactInterfaceRequired",
        ProtocolError::SessionStateRejected => "SessionStateRejected",
        ProtocolError::SessionIdMismatch => "SessionIdMismatch",
        ProtocolError::SequenceRejected => "SequenceRejected",
        ProtocolError::ModeOrOperationRejected => "ModeOrOperationRejected",
        ProtocolError::LifecycleRejected => "LifecycleRejected",
        ProtocolError::ProvisioningOrderRejected => "ProvisioningOrderRejected",
        ProtocolError::RecordRejected => "RecordRejected",
        ProtocolError::WalletBindingRejected => "WalletBindingRejected",
        ProtocolError::DerivationPathRejected => "DerivationPathRejected",
        ProtocolError::ChildDerivationRejected => "ChildDerivationRejected",
        ProtocolError::SigningBindingRejected => "SigningBindingRejected",
        ProtocolError::CryptographicOperationRejected => "CryptographicOperationRejected",
        ProtocolError::InternalIntegrityFailure => "InternalIntegrityFailure",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    assert_eq!(
        ProtocolError::from_status_word(error.status_word()),
        Some(error)
    );
    name
}

fn response_error_name(error: ResponseError) -> &'static str {
    let name = match error {
        ResponseError::Truncated => "ResponseTruncated",
        ResponseError::UnknownStatusWord => "ResponseUnknownStatusWord",
        ResponseError::RejectionHasBody => "ResponseRejectionHasBody",
        ResponseError::RejectionNotAllowed => "ResponseRejectionNotAllowed",
        ResponseError::SuccessLength => "ResponseSuccessLength",
        ResponseError::SuccessVersion => "ResponseSuccessVersion",
        ResponseError::SuccessEnvelope => "ResponseSuccessEnvelope",
        ResponseError::SuccessField => "ResponseSuccessField",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn record_error_name(error: RecordError) -> &'static str {
    let name = match error {
        RecordError::Length => "RecordLength",
        RecordError::Magic => "RecordMagic",
        RecordError::Version => "RecordVersion",
        RecordError::Profile => "RecordProfile",
        RecordError::Role => "RecordRole",
        RecordError::XprvVersion => "RecordXprvVersion",
        RecordError::XprvDepth => "RecordXprvDepth",
        RecordError::XprvChildNumber => "RecordXprvChildNumber",
        RecordError::XprvKeyPrefix => "RecordXprvKeyPrefix",
        RecordError::XprvScalar => "RecordXprvScalar",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn instruction(byte: u8) -> Instruction {
    const ALL: [Instruction; 10] = [
        Instruction::Select,
        Instruction::OpenSession,
        Instruction::GetInfo,
        Instruction::ReadDChunk,
        Instruction::ExportA2,
        Instruction::SignDigest,
        Instruction::BeginProvision,
        Instruction::WriteChunk,
        Instruction::Commit,
        Instruction::Abort,
    ];
    ALL[usize::from(byte) % ALL.len()]
}

fn fixture_requests(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let text = exact_fixture_line(data)?;
    let mut requests = Vec::new();
    for line in text.lines() {
        let (name, hex) = line.split_once(": ")?;
        if !name.ends_with("_request_hex") || hex.is_empty() || !hex.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let pair = core::str::from_utf8(pair).ok()?;
            bytes.push(u8::from_str_radix(pair, 16).ok()?);
        }
        requests.push(bytes);
    }
    (!requests.is_empty()).then_some(requests)
}

fn fixture_record(data: &[u8]) -> Option<Vec<u8>> {
    let text = exact_fixture_line(data)?;
    let (name, hex) = text.split_once(": ")?;
    if !name.starts_with("record_profile_") || !name.ends_with("_hex") {
        return None;
    }
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?);
    }
    Some(bytes)
}

fn fixture_response(data: &[u8]) -> Option<(Instruction, Vec<u8>)> {
    let text = exact_fixture_line(data)?;
    let (name, hex) = text.split_once(": ")?;
    let stem = name.strip_suffix("_response_hex")?;
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    let instruction = if stem.ends_with("_select") {
        Instruction::Select
    } else if stem.ends_with("_open") {
        Instruction::OpenSession
    } else if stem == "setup_begin" {
        Instruction::BeginProvision
    } else if stem.starts_with("setup_write_") {
        Instruction::WriteChunk
    } else if stem == "setup_commit" {
        Instruction::Commit
    } else if stem == "normal_info" {
        Instruction::GetInfo
    } else if stem.starts_with("normal_read_") {
        Instruction::ReadDChunk
    } else if stem == "normal_a2" {
        Instruction::ExportA2
    } else if stem.starts_with("normal_sign_") {
        Instruction::SignDigest
    } else {
        return None;
    };
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        bytes.push(u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?);
    }
    Some((instruction, bytes))
}

fn exercise_encoder_wipe(data: &[u8]) {
    let mut session_id = [0u8; 16];
    let copied = data.len().min(session_id.len());
    session_id[..copied].copy_from_slice(&data[..copied]);
    let mode = match data.first().copied().unwrap_or_default() % 4 {
        0 => Mode::Setup,
        1 => Mode::Normal,
        2 => Mode::KitRestore,
        3 => Mode::Rescue,
        _ => unreachable!("modulo four is exhaustive"),
    };
    let mut output = [0u8; MAX_REQUEST_BYTES];
    reset_wiped_bytes();
    let length = encode_open_session(mode, &session_id, &mut output).expect("fixed output fits");
    assert_eq!(length, 24);
    assert_eq!(wiped_bytes(), 18);
    assert!(parse_command(Media::ContactT1, &output[..length]).is_ok());
}

fn exercise_operation_table(selector: u8) {
    let lifecycle = match selector % 4 {
        0 => Lifecycle::Unprovisioned,
        1 => Lifecycle::Staging,
        2 => Lifecycle::Committed,
        3 => Lifecycle::RetiredError,
        _ => unreachable!("modulo four is exhaustive"),
    };
    let mode = match selector.wrapping_div(4) % 4 {
        0 => Mode::Setup,
        1 => Mode::Normal,
        2 => Mode::KitRestore,
        3 => Mode::Rescue,
        _ => unreachable!("modulo four is exhaustive"),
    };
    if let Err(error) = allowed_operations(lifecycle, mode, selector & 0x80 != 0) {
        assert_eq!(protocol_error_name(error), "LifecycleRejected");
    }
}

fuzz_target!(|data: &[u8]| {
    if let Some(record) = fixture_record(data) {
        parse_record(&record).expect("registered fixture record remains accepted");
        exercise_encoder_wipe(data);
        return;
    }
    if let Some((instruction, response)) = fixture_response(data) {
        parse_response(instruction, &response)
            .expect("registered fixture response remains accepted");
        exercise_encoder_wipe(data);
        return;
    }
    if let Some(requests) = fixture_requests(data) {
        for request in requests {
            let command = parse_command(Media::ContactT1, &request)
                .expect("registered fixture request remains accepted");
            assert_eq!(
                Instruction::from_byte(command.instruction().byte()),
                Some(command.instruction())
            );
        }
        exercise_encoder_wipe(data);
        return;
    }

    let selector = data.first().copied().unwrap_or_default();
    let candidate = data.get(1..).unwrap_or_default();
    let media = if selector & 1 == 0 {
        Media::ContactT1
    } else {
        Media::Contactless
    };

    match parse_command(media, candidate) {
        Ok(command) => {
            assert!(candidate.len() <= MAX_REQUEST_BYTES);
            assert_eq!(
                Instruction::from_byte(command.instruction().byte()),
                Some(command.instruction())
            );
        }
        Err(error) => {
            protocol_error_name(error);
            let mut encoded = [0u8; 2];
            assert_eq!(encode_rejection(error, &mut encoded), Ok(2));
            assert_eq!(
                StatusWord::from_value(u16::from_be_bytes(encoded)),
                Some(error.status_word())
            );
        }
    }

    let expected = instruction(selector.wrapping_div(2));
    if let Err(error) = parse_response(expected, candidate) {
        response_error_name(error);
    }
    if let Err(error) = parse_record(candidate) {
        record_error_name(error);
    }

    let mut one_byte = [0xa5];
    let before = one_byte;
    let error = encode_rejection(ProtocolError::WrongLength, &mut one_byte)
        .expect_err("one-byte rejection output");
    assert_eq!(error, EncodeError::OutputBufferTooSmall);
    assert_eq!(error.name(), "OutputBufferTooSmall");
    assert_eq!(error.to_string(), "OutputBufferTooSmall");
    assert_eq!(one_byte, before);

    exercise_encoder_wipe(candidate);
    exercise_operation_table(selector);
});
