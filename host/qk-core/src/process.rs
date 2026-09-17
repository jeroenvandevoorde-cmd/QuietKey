//! Real HOST child boundary for the trusted qk-core process.

use crate::card_apdu_session_v2::{
    CardApduExchangeV2, CardApduSessionErrorV2, CardApduSessionV2, CardSignatureReply,
};
use crate::wipe::{self, WipingArray};
use crate::{
    CardPresence, CardProcessErrorV1, CoreDeviceGrants, CoreError, CoreMode, CoreReceiveEvent,
    CoreSession, Interruption, MockCardSlot, MockDisplay, MockKeypad, NormalCardBDataV2,
    NormalCardBSigningRequestV2, NormalErrorV2, NormalProcessControllerV2, NormalProcessErrorV2,
    NormalProcessEventV2, NormalProcessStageV2, NormalProfileV2, NormalScreenV2, NormalStageV2,
};
use qk_card_protocol::{
    EncodeError, ProtocolError, ResponseError, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use qk_device_wire::{
    BodyRef, Capability, DeviceError, ExchangeProtocol, KeypadBody, LogicalKey, MessageKind,
    OneWayProtocol, ReceivedFrame, StreamDecoder, HEADER_BYTES as DEVICE_HEADER_BYTES,
    MAX_DISPLAY_BODY_BYTES,
};
use qk_ipc::{inherited_endpoint, receive_bytes_once, IpcError, UnixReceiveError};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

const RECEIVE_BYTES: usize = 1;
const DISPLAY_FD: i32 = 3;
const KEYPAD_FD: i32 = 4;
const CARD_RESPONSE_FD: i32 = 5;
const CARD_REQUEST_FD: i32 = 6;

/// Closed HOST child failure surface. No variant contains transported bytes,
/// wallet facts, a session identity, or another secret-bearing value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreHostProcessError {
    Endpoint(UnixReceiveError),
    Core(CoreError),
    WriteFailed,
    DeviceOpenFailed,
    DeviceReadFailed,
    DeviceWriteFailed,
    Device(DeviceError),
    CardEncode(EncodeError),
    CardProtocol(ProtocolError),
    CardResponse(ResponseError),
    CardBinding(CardProcessErrorV1),
    CardSessionIdentityUnavailable,
    CardSessionIdentityExhausted,
    Normal(NormalProcessErrorV2),
    UnexpectedEvent,
    ConnectionClosed,
}

impl fmt::Display for CoreHostProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Core(error) => error.fmt(formatter),
            Self::WriteFailed => formatter.write_str("WriteFailed"),
            Self::DeviceOpenFailed => formatter.write_str("DeviceOpenFailed"),
            Self::DeviceReadFailed => formatter.write_str("DeviceReadFailed"),
            Self::DeviceWriteFailed => formatter.write_str("DeviceWriteFailed"),
            Self::Device(error) => error.fmt(formatter),
            Self::CardEncode(error) => error.fmt(formatter),
            Self::CardProtocol(error) => error.fmt(formatter),
            Self::CardResponse(error) => error.fmt(formatter),
            Self::CardBinding(error) => error.fmt(formatter),
            Self::CardSessionIdentityUnavailable => {
                formatter.write_str("CardSessionIdentityUnavailable")
            }
            Self::CardSessionIdentityExhausted => {
                formatter.write_str("CardSessionIdentityExhausted")
            }
            Self::Normal(error) => error.fmt(formatter),
            Self::UnexpectedEvent => formatter.write_str("UnexpectedEvent"),
            Self::ConnectionClosed => formatter.write_str("ConnectionClosed"),
        }
    }
}

impl std::error::Error for CoreHostProcessError {}

/// Run the exact open/ready/close/closed control cycle over the inherited
/// connected Unix endpoint. The supervisor has already installed and checked
/// the fixed mock-device descriptors before this entrypoint executes.
pub fn run_core_host_process(mode: CoreMode) -> Result<(), CoreHostProcessError> {
    let stream = inherited_endpoint().map_err(CoreHostProcessError::Endpoint)?;
    run_control_cycle(&stream, mode)
}

/// Run the complete QK-DEC-161 Normal process cycle over QKIP, the four fixed
/// inherited QKDV descriptors, and the byte-complete HOST card protocol.
pub fn run_normal_core_host_process(profile_ascii: &[u8]) -> Result<(), CoreHostProcessError> {
    let stream = inherited_endpoint().map_err(CoreHostProcessError::Endpoint)?;
    let mut devices = NormalDeviceRuntime::open()?;
    let mut controller =
        NormalProcessControllerV2::start(profile_ascii).map_err(CoreHostProcessError::Normal)?;

    let card = devices.bind_normal_card(controller.selected_profile())?;
    controller
        .accept_profile(profile_wire(controller.selected_profile()))
        .map_err(CoreHostProcessError::Normal)?;
    let opening = controller
        .accept_bound_card(card)
        .map_err(CoreHostProcessError::Normal)?;
    devices.display_updates(&mut controller)?;
    drive_qkip(&stream, &mut controller, opening)?;

    loop {
        if controller.stage() == NormalProcessStageV2::Normal(NormalStageV2::CardBSigning) {
            let request = controller
                .card_b_signing_request()
                .ok_or(CoreHostProcessError::UnexpectedEvent)?;
            let mut reply = match devices.sign_card_b(&request) {
                Ok(reply) => reply,
                Err(error) => {
                    drop(request);
                    controller.terminate_operation(NormalErrorV2::SigningRejected);
                    let _ = devices.display_updates(&mut controller);
                    return Err(error);
                }
            };
            drop(request);
            let review_hash = reply.review_hash;
            let input_index = reply.input_index;
            let public_key = reply.public_key;
            let signature = reply
                .signature_mut()
                .ok_or(CoreHostProcessError::UnexpectedEvent)?;
            let outbound = match controller.accept_card_b_signature(
                review_hash,
                input_index,
                public_key,
                signature,
            ) {
                Ok(outbound) => outbound,
                Err(error) => {
                    drop(reply);
                    devices.application_session.terminate();
                    let _ = devices.display_updates(&mut controller);
                    return Err(CoreHostProcessError::Normal(error));
                }
            };
            drop(reply);
            if let Some(outbound) = outbound {
                drive_qkip(&stream, &mut controller, outbound)?;
            }
            continue;
        }
        devices.display_updates(&mut controller)?;
        match controller.stage() {
            NormalProcessStageV2::Normal(NormalStageV2::CompletedWiped) => return Ok(()),
            NormalProcessStageV2::Normal(NormalStageV2::FactorB)
            | NormalProcessStageV2::Normal(NormalStageV2::FactorA1) => {
                let before = controller.stage();
                let outbound = match controller.advance_automatic() {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        devices.application_session.terminate();
                        let _ = devices.display_updates(&mut controller);
                        return Err(CoreHostProcessError::Normal(error));
                    }
                };
                if let Some(outbound) = outbound {
                    if controller.stage() != before {
                        devices.display_updates(&mut controller)?;
                    }
                    drive_qkip(&stream, &mut controller, outbound)?;
                }
            }
            NormalProcessStageV2::Normal(_) => {
                let event = devices.read_keypad_event()?;
                let before = controller.stage();
                let outbound = match controller.handle_event(event) {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        devices.application_session.terminate();
                        let _ = devices.display_updates(&mut controller);
                        return Err(CoreHostProcessError::Normal(error));
                    }
                };
                if let Some(outbound) = outbound {
                    if controller.stage() != before {
                        devices.display_updates(&mut controller)?;
                    }
                    drive_qkip(&stream, &mut controller, outbound)?;
                }
            }
            NormalProcessStageV2::AwaitingProfile
            | NormalProcessStageV2::AwaitingNormalFactor
            | NormalProcessStageV2::Terminated => {
                return Err(CoreHostProcessError::UnexpectedEvent)
            }
        }
    }
}

struct NormalDeviceRuntime {
    display_file: File,
    keypad_file: File,

    display_protocol: OneWayProtocol,
    keypad_decoder: StreamDecoder,
    card: QkdvCardRuntime,
    application_session: CardApduSessionV2,
}

impl NormalDeviceRuntime {
    fn open() -> Result<Self, CoreHostProcessError> {
        Ok(Self {
            display_file: inherited_file(DISPLAY_FD, false)?,
            keypad_file: inherited_file(KEYPAD_FD, true)?,

            display_protocol: OneWayProtocol::new(Capability::Display),
            keypad_decoder: StreamDecoder::new(Capability::Keypad),
            card: QkdvCardRuntime {
                card_response_file: inherited_file(CARD_RESPONSE_FD, true)?,
                card_request_file: inherited_file(CARD_REQUEST_FD, false)?,
                card_protocol: ExchangeProtocol::new(
                    Capability::CardRequest,
                    Capability::CardResponse,
                )
                .map_err(CoreHostProcessError::Device)?,
                card_decoder: StreamDecoder::new(Capability::CardResponse),
            },
            application_session: CardApduSessionV2::new(),
        })
    }

    fn bind_normal_card(
        &mut self,
        selected_profile: NormalProfileV2,
    ) -> Result<NormalCardBDataV2, CoreHostProcessError> {
        self.application_session
            .bind_normal_card(&mut self.card, selected_profile)
            .map_err(map_card_application_error)
    }

    fn sign_card_b(
        &mut self,
        request: &NormalCardBSigningRequestV2,
    ) -> Result<CardSignatureReply, CoreHostProcessError> {
        self.application_session
            .sign_card_b(&mut self.card, request)
            .map_err(map_card_application_error)
    }

    fn display_updates(
        &mut self,
        controller: &mut NormalProcessControllerV2,
    ) -> Result<(), CoreHostProcessError> {
        while let Some(stage) = controller.take_display_stage() {
            self.display_stage(stage)?;
        }
        match controller.screen() {
            Some(NormalScreenV2::Stage(_)) => Ok(()),
            Some(screen) => self.display_screen(screen),
            None => Err(CoreHostProcessError::UnexpectedEvent),
        }
    }

    fn display_stage(&mut self, stage: NormalStageV2) -> Result<(), CoreHostProcessError> {
        self.display_screen(NormalScreenV2::Stage(stage))
    }

    fn display_screen(&mut self, screen: NormalScreenV2<'_>) -> Result<(), CoreHostProcessError> {
        let mut body = WipingArray::<MAX_DISPLAY_BODY_BYTES>::zeroed();
        let (kind, body_len) =
            crate::normal_process_v2::encode_display_body(screen, body.as_mut_array())
                .map_err(NormalProcessErrorV2::from)
                .map_err(CoreHostProcessError::Normal)?;
        let outbound = self
            .display_protocol
            .next(kind)
            .map_err(CoreHostProcessError::Device)?;
        let mut frame = WipingArray::<{ DEVICE_HEADER_BYTES + MAX_DISPLAY_BODY_BYTES }>::zeroed();
        let length = outbound
            .encode(
                body.as_array()
                    .get(..body_len)
                    .ok_or(CoreHostProcessError::UnexpectedEvent)?,
                frame.as_mut_array(),
            )
            .map_err(CoreHostProcessError::Device)?;
        self.display_file
            .write_all(
                frame
                    .as_array()
                    .get(..length)
                    .ok_or(CoreHostProcessError::UnexpectedEvent)?,
            )
            .map_err(|_| CoreHostProcessError::DeviceWriteFailed)?;
        drop(frame);
        drop(body);
        Ok(())
    }

    fn read_keypad_event(&mut self) -> Result<NormalProcessEventV2, CoreHostProcessError> {
        let frame = read_device_frame(&mut self.keypad_file, &mut self.keypad_decoder)?;
        match frame.parsed_body().map_err(CoreHostProcessError::Device)? {
            BodyRef::Keypad(body) => map_keypad(body),
            _ => Err(CoreHostProcessError::UnexpectedEvent),
        }
    }
}

fn inherited_file(descriptor: i32, read: bool) -> Result<File, CoreHostProcessError> {
    let path = format!("/dev/fd/{descriptor}");
    let mut options = OpenOptions::new();
    options.read(read).write(!read);
    options
        .open(path)
        .map_err(|_| CoreHostProcessError::DeviceOpenFailed)
}

fn read_device_frame(
    file: &mut File,
    decoder: &mut StreamDecoder,
) -> Result<ReceivedFrame, CoreHostProcessError> {
    let mut byte = WipingArray::<1>::zeroed();
    loop {
        match file.read_exact(byte.as_mut_array()) {
            Ok(()) => {}
            Err(_) => {
                let error = decoder.finish();
                return Err(CoreHostProcessError::Device(error));
            }
        }
        let outcome = decoder.ingest(byte.as_array());
        wipe::bytes(byte.as_mut_array());
        let outcome = outcome.map_err(CoreHostProcessError::Device)?;
        if outcome.frame_ready() {
            return decoder.take_frame().map_err(CoreHostProcessError::Device);
        }
    }
}

fn map_keypad(body: KeypadBody) -> Result<NormalProcessEventV2, CoreHostProcessError> {
    Ok(match body {
        KeypadBody::LogicalKey(key) => NormalProcessEventV2::LogicalKey(map_logical_key(key)),
        KeypadBody::SelectPsbtSource(source) => {
            NormalProcessEventV2::SelectPsbtSource(match source {
                qk_device_wire::Source::CameraBbqrPsbt => crate::Source::CameraBbqrPsbt,
                qk_device_wire::Source::MediaPsbt => crate::Source::MediaPsbt,
                _ => return Err(CoreHostProcessError::UnexpectedEvent),
            })
        }
        KeypadBody::HoldCompleted => NormalProcessEventV2::HoldCompleted,
        KeypadBody::SelectSd { caller_nonce } => NormalProcessEventV2::SelectSd { caller_nonce },
        KeypadBody::SelectBbqr { non_final_part_len } => {
            NormalProcessEventV2::SelectBbqr { non_final_part_len }
        }
        KeypadBody::CardRemoved => NormalProcessEventV2::CardRemoved,
        KeypadBody::SessionTimeout => NormalProcessEventV2::SessionTimeout,
    })
}

const fn map_logical_key(key: LogicalKey) -> crate::KeypadKey {
    match key {
        LogicalKey::Seven => crate::KeypadKey::Seven,
        LogicalKey::EightUp => crate::KeypadKey::EightUp,
        LogicalKey::Nine => crate::KeypadKey::Nine,
        LogicalKey::CeDelete => crate::KeypadKey::CeDelete,
        LogicalKey::CancelBack => crate::KeypadKey::CancelBack,
        LogicalKey::FourLeft => crate::KeypadKey::FourLeft,
        LogicalKey::Five => crate::KeypadKey::Five,
        LogicalKey::SixRight => crate::KeypadKey::SixRight,
        LogicalKey::Multiply => crate::KeypadKey::Multiply,
        LogicalKey::Divide => crate::KeypadKey::Divide,
        LogicalKey::One => crate::KeypadKey::One,
        LogicalKey::TwoDown => crate::KeypadKey::TwoDown,
        LogicalKey::Three => crate::KeypadKey::Three,
        LogicalKey::Minus => crate::KeypadKey::Minus,
        LogicalKey::Percent => crate::KeypadKey::Percent,
        LogicalKey::Zero => crate::KeypadKey::Zero,
        LogicalKey::Decimal => crate::KeypadKey::Decimal,
        LogicalKey::Plus => crate::KeypadKey::Plus,
        LogicalKey::EqualsConfirmEnter => crate::KeypadKey::EqualsConfirmEnter,
    }
}

struct QkdvCardRuntime {
    card_response_file: File,
    card_request_file: File,
    card_protocol: ExchangeProtocol,
    card_decoder: StreamDecoder,
}

impl QkdvCardRuntime {
    fn raw_card_exchange(&mut self, body: &[u8]) -> Result<ReceivedFrame, CoreHostProcessError> {
        let request = self
            .card_protocol
            .begin(MessageKind::CardApduRequest)
            .map_err(CoreHostProcessError::Device)?;
        let mut bytes = WipingArray::<{ DEVICE_HEADER_BYTES + MAX_REQUEST_BYTES }>::zeroed();
        let length = request
            .encode(body, bytes.as_mut_array())
            .map_err(CoreHostProcessError::Device)?;
        self.card_request_file
            .write_all(
                bytes
                    .as_array()
                    .get(..length)
                    .ok_or(CoreHostProcessError::UnexpectedEvent)?,
            )
            .map_err(|_| CoreHostProcessError::DeviceWriteFailed)?;
        drop(bytes);
        let frame = read_device_frame(&mut self.card_response_file, &mut self.card_decoder)?;
        raw_card_response(&frame)?;
        self.card_protocol
            .accept_response(&frame)
            .map_err(CoreHostProcessError::Device)?;
        Ok(frame)
    }
}

impl CardApduExchangeV2 for QkdvCardRuntime {
    type Error = CoreHostProcessError;

    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_RESPONSE_BYTES],
    ) -> Result<usize, Self::Error> {
        let frame = self.raw_card_exchange(request)?;
        let bytes = raw_card_response(&frame)?;
        response
            .get_mut(..bytes.len())
            .ok_or(CoreHostProcessError::UnexpectedEvent)?
            .copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

fn map_card_application_error(
    error: CardApduSessionErrorV2<CoreHostProcessError>,
) -> CoreHostProcessError {
    match error {
        CardApduSessionErrorV2::Transport(error) => error,
        CardApduSessionErrorV2::CardEncode(error) => CoreHostProcessError::CardEncode(error),
        CardApduSessionErrorV2::CardProtocol(error) => CoreHostProcessError::CardProtocol(error),
        CardApduSessionErrorV2::CardResponse(error) => CoreHostProcessError::CardResponse(error),
        CardApduSessionErrorV2::CardBinding(error) => CoreHostProcessError::CardBinding(error),
        CardApduSessionErrorV2::CardSessionIdentityUnavailable => {
            CoreHostProcessError::CardSessionIdentityUnavailable
        }
        CardApduSessionErrorV2::CardSessionIdentityExhausted => {
            CoreHostProcessError::CardSessionIdentityExhausted
        }
        CardApduSessionErrorV2::SigningRejected => CoreHostProcessError::Normal(
            NormalProcessErrorV2::Normal(NormalErrorV2::SigningRejected),
        ),
        CardApduSessionErrorV2::UnexpectedEvent => CoreHostProcessError::UnexpectedEvent,
    }
}

fn raw_card_response(frame: &ReceivedFrame) -> Result<&[u8], CoreHostProcessError> {
    match frame.parsed_body().map_err(CoreHostProcessError::Device)? {
        BodyRef::CardApduResponse(bytes) => Ok(bytes),
        _ => Err(CoreHostProcessError::UnexpectedEvent),
    }
}

const fn profile_wire(profile: NormalProfileV2) -> u8 {
    match profile {
        NormalProfileV2::SimpleRecovery => 0x01,
        NormalProfileV2::Inheritance => 0x02,
        NormalProfileV2::QuantumShelter => 0x03,
    }
}

fn drive_qkip(
    stream: &UnixStream,
    controller: &mut NormalProcessControllerV2,
    mut outbound: crate::CoreOutbound,
) -> Result<(), CoreHostProcessError> {
    loop {
        let mut writer = stream;
        writer
            .write_all(outbound.frame_bytes())
            .map_err(|_| CoreHostProcessError::WriteFailed)?;
        drop(outbound);
        let before = controller.stage();
        let next = receive_normal_qkip(stream, controller, before)?;
        match next {
            Some(value) => outbound = value,
            None => return Ok(()),
        }
    }
}

fn receive_normal_qkip(
    stream: &UnixStream,
    controller: &mut NormalProcessControllerV2,
    before: NormalProcessStageV2,
) -> Result<Option<crate::CoreOutbound>, CoreHostProcessError> {
    let mut scratch = WipingArray::<RECEIVE_BYTES>::zeroed();
    loop {
        let received = match receive_bytes_once(stream, scratch.as_mut_array()) {
            Ok(received) => received,
            Err(error) => {
                if error == UnixReceiveError::Ipc(IpcError::AncillaryData) {
                    let _ = controller.receive_qkip(&[], true);
                } else {
                    controller.peer_lost();
                }
                return Err(CoreHostProcessError::Endpoint(error));
            }
        };
        if received == 0 {
            controller.peer_lost();
            return Err(CoreHostProcessError::ConnectionClosed);
        }
        let input = scratch
            .as_array()
            .get(..received)
            .ok_or(CoreHostProcessError::UnexpectedEvent)?;
        let next = controller.receive_qkip(input, false);
        wipe::bytes(scratch.as_mut_array());
        let next = next.map_err(CoreHostProcessError::Normal)?;
        if next.is_some() || controller.stage() != before {
            return Ok(next);
        }
    }
}

fn run_control_cycle(stream: &UnixStream, mode: CoreMode) -> Result<(), CoreHostProcessError> {
    let grants = CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .map_err(CoreHostProcessError::Core)?;
    let (mut session, opening) =
        CoreSession::start(mode, grants).map_err(CoreHostProcessError::Core)?;
    write_frame(stream, opening.frame_bytes(), &mut session)?;
    if receive_event(stream, &mut session)? != CoreReceiveEvent::SessionReady {
        terminate_unexpected(&mut session);
        return Err(CoreHostProcessError::UnexpectedEvent);
    }

    let closing = session.begin_close().map_err(CoreHostProcessError::Core)?;
    write_frame(stream, closing.frame_bytes(), &mut session)?;
    if receive_event(stream, &mut session)? != CoreReceiveEvent::SessionClosed {
        terminate_unexpected(&mut session);
        return Err(CoreHostProcessError::UnexpectedEvent);
    }
    Ok(())
}

fn write_frame(
    stream: &UnixStream,
    frame: &[u8],
    session: &mut CoreSession,
) -> Result<(), CoreHostProcessError> {
    let mut writer = stream;
    if writer.write_all(frame).is_err() {
        terminate_unexpected(session);
        return Err(CoreHostProcessError::WriteFailed);
    }
    Ok(())
}

fn receive_event(
    stream: &UnixStream,
    session: &mut CoreSession,
) -> Result<CoreReceiveEvent, CoreHostProcessError> {
    let mut scratch = WipingArray::<RECEIVE_BYTES>::zeroed();
    loop {
        let received = match receive_bytes_once(stream, scratch.as_mut_array()) {
            Ok(0) => {
                let _ = session.connection_closed();
                return Err(CoreHostProcessError::ConnectionClosed);
            }
            Ok(received) => received,
            Err(error) => {
                latch_receive_failure(session, error);
                return Err(CoreHostProcessError::Endpoint(error));
            }
        };
        let input = match scratch.as_array().get(..received) {
            Some(input) => input,
            None => {
                terminate_unexpected(session);
                return Err(CoreHostProcessError::UnexpectedEvent);
            }
        };
        let result = session.receive(input, false);
        wipe::bytes(scratch.as_mut_array());
        let outcome = result.map_err(CoreHostProcessError::Core)?;
        if outcome.event() != CoreReceiveEvent::NeedMore {
            return Ok(outcome.event());
        }
    }
}

fn latch_receive_failure(session: &mut CoreSession, error: UnixReceiveError) {
    if error == UnixReceiveError::Ipc(IpcError::AncillaryData) {
        let _ = session.receive(&[], true);
    } else {
        terminate_unexpected(session);
    }
}

fn terminate_unexpected(session: &mut CoreSession) {
    let _ = session.interrupt(Interruption::OperationFailed);
}

#[cfg(test)]
mod tests {
    use super::{read_device_frame, CoreHostProcessError, NormalDeviceRuntime, QkdvCardRuntime};
    use crate::card_apdu_session_v2::CardApduSessionV2;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::{NormalProfileV2, NormalScreenV2, NormalStageV2};
    use qk_card_protocol::{
        encode_success, parse_command, EnvelopeRef, Instruction, Lifecycle, Media, Mode, Profile,
        MAX_RESPONSE_BYTES, PROTOCOL_VERSION, RECORD_VERSION, ROLE_KEY_CARD_B,
    };
    use qk_device_wire::{
        BodyRef, Capability, ExchangeProtocol, MessageKind, OneWayProtocol, StreamDecoder,
        HEADER_BYTES as DEVICE_HEADER_BYTES, MAX_CARD_APDU_RESPONSE_BODY_BYTES,
    };
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn null_file(read: bool) -> File {
        OpenOptions::new()
            .read(read)
            .write(!read)
            .open("/dev/null")
            .expect("open null device")
    }

    fn broken_writer() -> File {
        let (writer, peer) = UnixStream::pair().expect("socket pair");
        drop(peer);
        let descriptor: OwnedFd = writer.into();
        File::from(descriptor)
    }

    fn runtime(display_file: File, card_request_file: File) -> NormalDeviceRuntime {
        runtime_with_card(display_file, null_file(true), card_request_file)
    }

    fn runtime_with_card(
        display_file: File,
        card_response_file: File,
        card_request_file: File,
    ) -> NormalDeviceRuntime {
        NormalDeviceRuntime {
            display_file,
            keypad_file: null_file(true),

            display_protocol: OneWayProtocol::new(Capability::Display),
            keypad_decoder: StreamDecoder::new(Capability::Keypad),
            card: QkdvCardRuntime {
                card_response_file,
                card_request_file,
                card_protocol: ExchangeProtocol::new(
                    Capability::CardRequest,
                    Capability::CardResponse,
                )
                .expect("card exchange protocol"),
                card_decoder: StreamDecoder::new(Capability::CardResponse),
            },
            application_session: CardApduSessionV2::new(),
        }
    }

    fn write_card_response(file: &mut File, protocol: &mut OneWayProtocol, response: &[u8]) {
        let outbound = protocol
            .next(MessageKind::CardApduResponse)
            .expect("card response frame");
        let mut frame = [0u8; DEVICE_HEADER_BYTES + MAX_CARD_APDU_RESPONSE_BODY_BYTES];
        let length = outbound
            .encode(response, &mut frame)
            .expect("encode card response frame");
        file.write_all(&frame[..length])
            .expect("write card response frame");
    }

    fn mismatched_profile_info() -> [u8; 137] {
        let mut info = [0u8; 137];
        info[0] = PROTOCOL_VERSION;
        info[1] = RECORD_VERSION;
        info[2] = Lifecycle::Committed.byte();
        info[3] = Profile::Inheritance.byte();
        info[4] = ROLE_KEY_CARD_B;
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
        info[135..137].copy_from_slice(&0x000fu16.to_be_bytes());
        info
    }

    #[test]
    fn display_write_failure_drops_both_fixed_scratch_owners() {
        let mut runtime = runtime(broken_writer(), null_file(false));
        reset_wiped_bytes();
        assert!(matches!(
            runtime.display_screen(NormalScreenV2::Stage(NormalStageV2::NormalStart)),
            Err(CoreHostProcessError::DeviceWriteFailed)
        ));
        assert_eq!(
            wiped_bytes(),
            qk_device_wire::MAX_DISPLAY_BODY_BYTES
                + qk_device_wire::HEADER_BYTES
                + qk_device_wire::MAX_DISPLAY_BODY_BYTES
        );
    }

    #[test]
    fn card_request_write_failure_drops_the_fixed_frame_owner() {
        let mut runtime = runtime(null_file(false), broken_writer());
        reset_wiped_bytes();
        assert!(matches!(
            runtime.card.raw_card_exchange(&[]),
            Err(CoreHostProcessError::DeviceWriteFailed)
        ));
        assert_eq!(
            wiped_bytes(),
            qk_device_wire::HEADER_BYTES + qk_card_protocol::MAX_REQUEST_BYTES
        );
    }

    #[test]
    fn malformed_info_cannot_trigger_descriptor_or_a2_requests() {
        let (core_request, peer_request) = UnixStream::pair().expect("request socket pair");
        let (peer_response, core_response) = UnixStream::pair().expect("response socket pair");
        let request_descriptor: OwnedFd = core_request.into();
        let response_descriptor: OwnedFd = core_response.into();
        let mut runtime = runtime_with_card(
            null_file(false),
            File::from(response_descriptor),
            File::from(request_descriptor),
        );

        let peer = thread::spawn(move || {
            let request_descriptor: OwnedFd = peer_request.into();
            let response_descriptor: OwnedFd = peer_response.into();
            let mut requests = File::from(request_descriptor);
            let mut responses = File::from(response_descriptor);
            let mut decoder = StreamDecoder::new(Capability::CardRequest);
            let mut protocol = OneWayProtocol::new(Capability::CardResponse);
            let mut instructions = Vec::new();

            let select = read_device_frame(&mut requests, &mut decoder).expect("SELECT request");
            let BodyRef::CardApduRequest(select_bytes) =
                select.parsed_body().expect("SELECT QKDV body")
            else {
                panic!("wrong SELECT QKDV body");
            };
            let select_command =
                parse_command(Media::ContactT1, select_bytes).expect("SELECT command");
            instructions.push(select_command.instruction());
            assert_eq!(select_command.instruction(), Instruction::Select);
            let mut response = [0u8; MAX_RESPONSE_BYTES];
            let length = encode_success(None, &[], &mut response).expect("SELECT response");
            write_card_response(&mut responses, &mut protocol, &response[..length]);

            let open = read_device_frame(&mut requests, &mut decoder).expect("OPEN request");
            let BodyRef::CardApduRequest(open_bytes) = open.parsed_body().expect("OPEN QKDV body")
            else {
                panic!("wrong OPEN QKDV body");
            };
            let open_command = parse_command(Media::ContactT1, open_bytes).expect("OPEN command");
            instructions.push(open_command.instruction());
            let qk_card_protocol::CommandRef::OpenSession {
                mode: Mode::Normal,
                session_id,
            } = open_command
            else {
                panic!("wrong OPEN command");
            };
            let length = encode_success(Some(EnvelopeRef::new(session_id, 0)), &[], &mut response)
                .expect("OPEN response");
            write_card_response(&mut responses, &mut protocol, &response[..length]);

            let info = read_device_frame(&mut requests, &mut decoder).expect("GET_INFO request");
            let BodyRef::CardApduRequest(info_bytes) =
                info.parsed_body().expect("GET_INFO QKDV body")
            else {
                panic!("wrong GET_INFO QKDV body");
            };
            let info_command =
                parse_command(Media::ContactT1, info_bytes).expect("GET_INFO command");
            instructions.push(info_command.instruction());
            let qk_card_protocol::CommandRef::GetInfo { envelope } = info_command else {
                panic!("wrong GET_INFO command");
            };
            let length = encode_success(Some(envelope), &mismatched_profile_info(), &mut response)
                .expect("GET_INFO response");
            write_card_response(&mut responses, &mut protocol, &response[..length]);

            if let Ok(next) = read_device_frame(&mut requests, &mut decoder) {
                let BodyRef::CardApduRequest(next_bytes) =
                    next.parsed_body().expect("next QKDV body")
                else {
                    panic!("wrong next QKDV body");
                };
                instructions.push(
                    parse_command(Media::ContactT1, next_bytes)
                        .expect("next command")
                        .instruction(),
                );
            }
            instructions
        });

        let result = runtime.bind_normal_card(NormalProfileV2::SimpleRecovery);
        assert!(matches!(
            result,
            Err(CoreHostProcessError::CardBinding(
                crate::CardProcessErrorV1::InfoProfileMismatch
            ))
        ));
        assert!(runtime.application_session.is_terminated());
        drop(runtime);
        assert_eq!(
            peer.join().expect("card peer"),
            [
                Instruction::Select,
                Instruction::OpenSession,
                Instruction::GetInfo,
            ]
        );
    }
}
