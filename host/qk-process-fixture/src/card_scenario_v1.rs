//! Raw Key Card B fixture driver for the QK-DEC-161 process matrix.
//!
//! PERMANENTLY NEVER-FUND TEST MATERIAL. The model is provisioned only from
//! registered public known-private fixture material; this module creates no
//! new signing authority.

use crate::common::{CycleSpec, FixtureError, Negative, Profile};
use crate::wipe::{bytes as wipe_bytes, WipingVec};
use qk_card_model::{CardModel, RESPONSE_BYTES};
use qk_card_protocol::{
    encode_begin_provision, encode_commit, encode_export_a2, encode_get_info, encode_open_session,
    encode_read_d_chunk, encode_select, encode_write_chunk, parse_command, parse_response,
    A2Purpose, DescriptorSelector, EnvelopeRef, Instruction, Media, Mode, ProtocolError,
    ResponseRef, MAX_REQUEST_BYTES, RECORD_BYTES,
};
use qk_device_wire::{
    BodyRef, Capability, MessageKind, OneWayProtocol, StreamDecoder, HEADER_BYTES,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

const CARD_FIXTURE: &str =
    include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
const CARD_RESPONSE_FD: i32 = 5;
const CARD_REQUEST_FD: i32 = 6;
const SETUP_SESSION_ID: [u8; 16] = [0xa1; 16];
const VERIFY_SESSION_ID: [u8; 16] = [0xa3; 16];

pub struct CardScenarioV1 {
    model: CardModel,
    requests: File,
    responses: File,
    request_decoder: StreamDecoder,
    response_protocol: OneWayProtocol,
    spec: CycleSpec,
}

impl CardScenarioV1 {
    pub fn provisioned(spec: CycleSpec) -> Result<Self, FixtureError> {
        let provisioned_profile = if spec.negative == Some(Negative::ProfileMismatch) {
            match spec.profile {
                Profile::SimpleRecovery => Profile::Inheritance,
                Profile::Inheritance | Profile::QuantumShelter => Profile::SimpleRecovery,
            }
        } else {
            spec.profile
        };
        let model = provision_and_verify(provisioned_profile)?;
        Ok(Self {
            model,
            requests: open_fd(CARD_REQUEST_FD, true)?,
            responses: open_fd(CARD_RESPONSE_FD, false)?,
            request_decoder: StreamDecoder::new(Capability::CardRequest),
            response_protocol: OneWayProtocol::new(Capability::CardResponse),
            spec,
        })
    }

    /// Serve SELECT, OPEN, INFO, both descriptors, and A2. `false` means the
    /// selected hostile case has already produced its exact terminating reply.
    pub fn serve_normal_binding(&mut self) -> Result<bool, FixtureError> {
        let first = match self.spec.negative {
            Some(Negative::CardMedia) => Mutation::Contactless,
            Some(Negative::CardApduFraming) => Mutation::MissingLe,
            Some(Negative::CardStatusPrecedence) => Mutation::ContactlessAndWrongCla,
            _ => Mutation::None,
        };
        self.exchange(Instruction::Select, first)?;
        if matches!(
            self.spec.negative,
            Some(Negative::CardMedia | Negative::CardApduFraming | Negative::CardStatusPrecedence)
        ) {
            return Ok(false);
        }

        self.exchange(Instruction::OpenSession, Mutation::None)?;
        let info_mutation = match self.spec.negative {
            Some(Negative::RecordMismatch) => Mutation::RecordVersion,
            Some(Negative::WrongWallet) => Mutation::WalletId,
            Some(Negative::SequenceMismatch) => Mutation::ResponseSequence,
            _ => Mutation::None,
        };
        self.exchange(Instruction::GetInfo, info_mutation)?;
        if matches!(
            self.spec.negative,
            Some(Negative::ProfileMismatch | Negative::RecordMismatch | Negative::SequenceMismatch)
        ) {
            return Ok(false);
        }

        for _ in 0..4 {
            self.exchange(Instruction::ReadDChunk, Mutation::None)?;
        }
        if self.spec.negative == Some(Negative::WrongWallet) {
            return Ok(false);
        }
        self.exchange(Instruction::ExportA2, Mutation::None)?;
        Ok(true)
    }

    pub fn serve_signature(&mut self) -> Result<(), FixtureError> {
        let mutation = match self.spec.negative {
            Some(Negative::HighSNormalization) => Mutation::HighS,
            Some(Negative::InvalidSignature) => Mutation::InvalidSignature,
            _ => Mutation::None,
        };
        self.exchange(Instruction::SignDigest, mutation)
    }

    pub fn require_request_eof(&mut self) -> Result<(), FixtureError> {
        let mut byte = [0u8; 1];
        let received = self
            .requests
            .read(&mut byte)
            .map_err(|_| FixtureError::Io)?;
        wipe_bytes(&mut byte);
        if received == 0 {
            Ok(())
        } else {
            Err(FixtureError::FactMismatch)
        }
    }

    fn exchange(&mut self, expected: Instruction, mutation: Mutation) -> Result<(), FixtureError> {
        let frame = read_frame(&mut self.requests, &mut self.request_decoder)?;
        let request = match frame.parsed_body().map_err(|_| FixtureError::Wire)? {
            BodyRef::CardApduRequest(bytes) => bytes,
            _ => return Err(FixtureError::FactMismatch),
        };
        let parsed = parse_command(Media::ContactT1, request).map_err(|_| FixtureError::Wire)?;
        if parsed.instruction() != expected {
            return Err(FixtureError::FactMismatch);
        }

        let mut altered = WipingVec::from_slice(request).map_err(|_| FixtureError::Fixture)?;
        let media = match mutation {
            Mutation::Contactless | Mutation::ContactlessAndWrongCla => Media::Contactless,
            _ => Media::ContactT1,
        };
        let request_len = match mutation {
            Mutation::MissingLe => altered.len().checked_sub(1).ok_or(FixtureError::Fixture)?,
            Mutation::ContactlessAndWrongCla => {
                altered.as_mut_slice()[0] ^= 0x01;
                altered.len()
            }
            _ => altered.len(),
        };
        if mutation == Mutation::HighS {
            self.model.emit_high_s_once();
        }

        let mut response = WipingVec::zeroed(RESPONSE_BYTES).map_err(|_| FixtureError::Fixture)?;
        let result = self.model.process_apdu(
            media,
            altered
                .as_slice()
                .get(..request_len)
                .ok_or(FixtureError::Fixture)?,
            response
                .as_mut_slice()
                .try_into()
                .map_err(|_| FixtureError::Fixture)?,
        );
        let response_len = match result {
            Ok(length) => {
                if matches!(
                    mutation,
                    Mutation::Contactless | Mutation::MissingLe | Mutation::ContactlessAndWrongCla
                ) {
                    return Err(FixtureError::FactMismatch);
                }
                length
            }
            Err(error) => {
                let expected_error = match mutation {
                    Mutation::Contactless | Mutation::ContactlessAndWrongCla => {
                        Some(ProtocolError::ContactInterfaceRequired)
                    }
                    Mutation::MissingLe => Some(ProtocolError::WrongLength),
                    _ => None,
                };
                if expected_error != Some(error)
                    || response.as_slice().get(..2) != Some(&error.status_word().bytes())
                {
                    return Err(FixtureError::FactMismatch);
                }
                2
            }
        };

        if result.is_ok() {
            {
                let parsed = parse_response(
                    expected,
                    response
                        .as_slice()
                        .get(..response_len)
                        .ok_or(FixtureError::Fixture)?,
                )
                .map_err(|_| FixtureError::Wire)?;
                if matches!(parsed, ResponseRef::Rejected(_)) {
                    return Err(FixtureError::FactMismatch);
                }
            }
            apply_response_mutation(mutation, response.as_mut_slice(), response_len)?;
        }

        write_protocol_frame(
            &mut self.responses,
            &mut self.response_protocol,
            MessageKind::CardApduResponse,
            response
                .as_slice()
                .get(..response_len)
                .ok_or(FixtureError::Fixture)?,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mutation {
    None,
    Contactless,
    MissingLe,
    ContactlessAndWrongCla,
    RecordVersion,
    WalletId,
    ResponseSequence,
    HighS,
    InvalidSignature,
}

fn apply_response_mutation(
    mutation: Mutation,
    response: &mut [u8],
    response_len: usize,
) -> Result<(), FixtureError> {
    match mutation {
        Mutation::None => Ok(()),
        Mutation::RecordVersion => {
            if !matches!(
                parse_response(Instruction::GetInfo, &response[..response_len])
                    .map_err(|_| FixtureError::FactMismatch)?,
                ResponseRef::GetInfo {
                    record_version: 1,
                    ..
                }
            ) {
                return Err(FixtureError::FactMismatch);
            }
            response[22] = 2;
            Ok(())
        }
        Mutation::WalletId => {
            if !matches!(
                parse_response(Instruction::GetInfo, &response[..response_len])
                    .map_err(|_| FixtureError::FactMismatch)?,
                ResponseRef::GetInfo { .. }
            ) {
                return Err(FixtureError::FactMismatch);
            }
            response[42] ^= 1;
            Ok(())
        }
        Mutation::ResponseSequence => {
            if !matches!(
                parse_response(Instruction::GetInfo, &response[..response_len])
                    .map_err(|_| FixtureError::FactMismatch)?,
                ResponseRef::GetInfo { .. }
            ) {
                return Err(FixtureError::FactMismatch);
            }
            response[20] = response[20].checked_add(1).ok_or(FixtureError::Fixture)?;
            Ok(())
        }
        Mutation::HighS => {
            {
                let ResponseRef::SignDigest { signature_der, .. } =
                    parse_response(Instruction::SignDigest, &response[..response_len])
                        .map_err(|_| FixtureError::FactMismatch)?
                else {
                    return Err(FixtureError::FactMismatch);
                };
                if signature_der.len() != 72
                    || signature_der.get(37..40) != Some(&[0x02, 0x21, 0x00])
                {
                    return Err(FixtureError::FactMismatch);
                }
            }
            Ok(())
        }
        Mutation::InvalidSignature => {
            let (start, length) = {
                let ResponseRef::SignDigest { signature_der, .. } =
                    parse_response(Instruction::SignDigest, &response[..response_len])
                        .map_err(|_| FixtureError::FactMismatch)?
                else {
                    return Err(FixtureError::FactMismatch);
                };
                if signature_der.len() < 16 {
                    return Err(FixtureError::FactMismatch);
                }
                (
                    signature_der.as_ptr() as usize - response.as_ptr() as usize,
                    signature_der.len(),
                )
            };
            let target = start.checked_add(length / 2).ok_or(FixtureError::Fixture)?;
            if target >= response_len.saturating_sub(2) {
                return Err(FixtureError::Fixture);
            }
            response[target] ^= 1;
            parse_response(Instruction::SignDigest, &response[..response_len])
                .map_err(|_| FixtureError::FactMismatch)?;
            Ok(())
        }
        Mutation::Contactless | Mutation::MissingLe | Mutation::ContactlessAndWrongCla => {
            Err(FixtureError::FactMismatch)
        }
    }
}

fn provision_and_verify(profile: Profile) -> Result<CardModel, FixtureError> {
    let mut model = CardModel::new();
    let mut record = hex_field(CARD_FIXTURE, profile.record_field())?;
    if record.len() != RECORD_BYTES {
        return Err(FixtureError::Fixture);
    }
    let nonce = fixed_array::<12>(&hex_field(CARD_FIXTURE, "provisioning_nonce_hex")?)?;
    let account_xpub = hex_field(CARD_FIXTURE, "account_xpub_raw_hex")?;

    expect_encoded(&mut model, Instruction::Select, encode_select, |value| {
        matches!(value, ResponseRef::Select)
    })?;
    expect_encoded(
        &mut model,
        Instruction::OpenSession,
        |out| encode_open_session(Mode::Setup, &SETUP_SESSION_ID, out),
        |value| matches!(value, ResponseRef::OpenSession { envelope } if envelope == EnvelopeRef::new(&SETUP_SESSION_ID, 0)),
    )?;
    expect_encoded(
        &mut model,
        Instruction::BeginProvision,
        |out| encode_begin_provision(EnvelopeRef::new(&SETUP_SESSION_ID, 1), 1, &nonce, out),
        |value| matches!(value, ResponseRef::BeginProvision { .. }),
    )?;
    for (index, (offset, width)) in [
        (0usize, 192usize),
        (192, 192),
        (384, 192),
        (576, 192),
        (768, 13),
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(2))
            .ok_or(FixtureError::Fixture)?;
        expect_encoded(
            &mut model,
            Instruction::WriteChunk,
            |out| {
                encode_write_chunk(
                    EnvelopeRef::new(&SETUP_SESSION_ID, sequence),
                    u16::try_from(offset)
                        .map_err(|_| qk_card_protocol::EncodeError::ValueOutOfRange)?,
                    &record.as_slice()[offset..offset + width],
                    out,
                )
            },
            |value| matches!(value, ResponseRef::WriteChunk { next_offset, .. } if usize::from(next_offset) == offset + width),
        )?;
    }
    expect_encoded(
        &mut model,
        Instruction::Commit,
        |out| encode_commit(EnvelopeRef::new(&SETUP_SESSION_ID, 7), out),
        |value| matches!(value, ResponseRef::Commit { .. }),
    )?;

    expect_encoded(&mut model, Instruction::Select, encode_select, |value| {
        matches!(value, ResponseRef::Select)
    })?;
    expect_encoded(
        &mut model,
        Instruction::OpenSession,
        |out| encode_open_session(Mode::Setup, &VERIFY_SESSION_ID, out),
        |value| matches!(value, ResponseRef::OpenSession { envelope } if envelope == EnvelopeRef::new(&VERIFY_SESSION_ID, 0)),
    )?;
    expect_encoded(
        &mut model,
        Instruction::GetInfo,
        |out| encode_get_info(EnvelopeRef::new(&VERIFY_SESSION_ID, 1), out),
        |value| {
            matches!(
                value,
                ResponseRef::GetInfo {
                    record_version: 1,
                    lifecycle: 2,
                    profile: actual_profile,
                    role: 2,
                    instance_id,
                    wallet_id,
                    origin_fingerprint,
                    account_xpub: actual_xpub,
                    allowed_operations: 0x0007,
                    ..
                } if actual_profile == profile.wire()
                    && instance_id == &record.as_slice()[7..23]
                    && wallet_id == &record.as_slice()[23..55]
                    && origin_fingerprint == &record.as_slice()[55..59]
                    && actual_xpub == account_xpub.as_slice()
            )
        },
    )?;
    for (sequence, selector, offset, expected) in [
        (
            2,
            DescriptorSelector::Receive,
            0,
            &record.as_slice()[169..361],
        ),
        (
            3,
            DescriptorSelector::Receive,
            192,
            &record.as_slice()[361..475],
        ),
        (
            4,
            DescriptorSelector::Change,
            0,
            &record.as_slice()[475..667],
        ),
        (
            5,
            DescriptorSelector::Change,
            192,
            &record.as_slice()[667..781],
        ),
    ] {
        expect_encoded(
            &mut model,
            Instruction::ReadDChunk,
            |out| {
                encode_read_d_chunk(
                    EnvelopeRef::new(&VERIFY_SESSION_ID, sequence),
                    selector,
                    offset,
                    out,
                )
            },
            |value| matches!(value, ResponseRef::ReadDChunk { bytes, .. } if bytes == expected),
        )?;
    }
    expect_encoded(
        &mut model,
        Instruction::ExportA2,
        |out| {
            encode_export_a2(
                EnvelopeRef::new(&VERIFY_SESSION_ID, 6),
                A2Purpose::Setup,
                out,
            )
        },
        |value| matches!(value, ResponseRef::ExportA2 { a2, .. } if a2 == &record.as_slice()[137..169]),
    )?;
    wipe_bytes(record.as_mut_slice());
    Ok(model)
}

fn expect_encoded(
    model: &mut CardModel,
    instruction: Instruction,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, qk_card_protocol::EncodeError>,
    check: impl FnOnce(ResponseRef<'_>) -> bool,
) -> Result<(), FixtureError> {
    let mut command = WipingVec::zeroed(MAX_REQUEST_BYTES).map_err(|_| FixtureError::Fixture)?;
    let length = encode(command.as_mut_slice()).map_err(|_| FixtureError::Fixture)?;
    let mut response = WipingVec::zeroed(RESPONSE_BYTES).map_err(|_| FixtureError::Fixture)?;
    let response_length = model
        .process_apdu(
            Media::ContactT1,
            &command.as_slice()[..length],
            response
                .as_mut_slice()
                .try_into()
                .map_err(|_| FixtureError::Fixture)?,
        )
        .map_err(|_| FixtureError::FactMismatch)?;
    let parsed = parse_response(instruction, &response.as_slice()[..response_length])
        .map_err(|_| FixtureError::FactMismatch)?;
    if check(parsed) {
        Ok(())
    } else {
        Err(FixtureError::FactMismatch)
    }
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

fn open_fd(descriptor: i32, read: bool) -> Result<File, FixtureError> {
    let mut options = OpenOptions::new();
    options.read(read).write(!read);
    options
        .open(format!("/dev/fd/{descriptor}"))
        .map_err(|_| FixtureError::Io)
}

fn field<'a>(source: &'a str, name: &str) -> Result<&'a str, FixtureError> {
    source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(": "))
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .ok_or(FixtureError::Fixture)
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

fn fixed_array<const N: usize>(value: &WipingVec) -> Result<[u8; N], FixtureError> {
    value
        .as_slice()
        .try_into()
        .map_err(|_| FixtureError::Fixture)
}

impl Profile {
    const fn record_field(self) -> &'static str {
        match self {
            Self::SimpleRecovery => "record_profile_01_hex",
            Self::Inheritance => "record_profile_02_hex",
            Self::QuantumShelter => "record_profile_03_hex",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_is_provisioned_and_verified_through_raw_setup_apdus() {
        for profile in Profile::ALL {
            let model = provision_and_verify(profile).expect("registered Setup trace");
            assert_eq!(model.lifecycle(), qk_card_model::ModelLifecycle::Committed);
        }
    }

    #[test]
    fn fixture_records_are_exact_and_publicly_labeled() {
        assert!(CARD_FIXTURE.contains("PERMANENTLY NEVER-FUND TEST MATERIAL"));
        for profile in Profile::ALL {
            assert_eq!(
                hex_field(CARD_FIXTURE, profile.record_field())
                    .expect("registered record")
                    .len(),
                RECORD_BYTES
            );
        }
    }
}
