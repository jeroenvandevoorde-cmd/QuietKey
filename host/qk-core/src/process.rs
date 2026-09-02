//! Real HOST child boundary for the trusted qk-core process.

use crate::wipe::{self, WipingArray};
use crate::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreReceiveEvent, CoreSession,
    Interruption, MockCardSlot, MockDisplay, MockKeypad, NormalProcessControllerV2,
    NormalProcessErrorV2, NormalProcessEventV2, NormalProcessStageV2, NormalScreenV2,
    NormalStageV2,
};
use qk_device_wire::{
    BodyRef, Capability, CardResponseBody, DeviceError, DeviceRejection, ExchangeProtocol,
    KeypadBody, LogicalKey, MessageKind, OneWayProtocol, Profile, ReceivedFrame, StreamDecoder,
    HEADER_BYTES as DEVICE_HEADER_BYTES, MAX_DISPLAY_BODY_BYTES,
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

/// Run the complete QK-DEC-156 Normal process cycle over QKIP and the four
/// fixed inherited QKDV descriptors.
pub fn run_normal_core_host_process(profile_ascii: &[u8]) -> Result<(), CoreHostProcessError> {
    let stream = inherited_endpoint().map_err(CoreHostProcessError::Endpoint)?;
    let mut devices = NormalDeviceRuntime::open()?;
    let mut controller =
        NormalProcessControllerV2::start(profile_ascii).map_err(CoreHostProcessError::Normal)?;

    let profile = devices.read_card_profile()?;
    controller
        .accept_profile(profile.wire_value())
        .map_err(CoreHostProcessError::Normal)?;
    let factor = devices.read_normal_factor()?;
    let opening = controller.accept_normal_factor(factor.body());
    drop(factor);
    let opening = opening.map_err(CoreHostProcessError::Normal)?;
    devices.display_updates(&mut controller)?;
    drive_qkip(&stream, &mut controller, opening)?;

    loop {
        devices.display_updates(&mut controller)?;
        match controller.stage() {
            NormalProcessStageV2::Normal(NormalStageV2::CompletedWiped) => return Ok(()),
            NormalProcessStageV2::Normal(NormalStageV2::FactorB)
            | NormalProcessStageV2::Normal(NormalStageV2::FactorA1) => {
                let before = controller.stage();
                if let Some(outbound) = controller
                    .advance_automatic()
                    .map_err(CoreHostProcessError::Normal)?
                {
                    if controller.stage() != before {
                        devices.display_updates(&mut controller)?;
                    }
                    drive_qkip(&stream, &mut controller, outbound)?;
                }
            }
            NormalProcessStageV2::Normal(_) => {
                let event = devices.read_keypad_event()?;
                let before = controller.stage();
                if let Some(outbound) = controller
                    .handle_event(event)
                    .map_err(CoreHostProcessError::Normal)?
                {
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
    card_response_file: File,
    card_request_file: File,
    display_protocol: OneWayProtocol,
    keypad_decoder: StreamDecoder,
    card_protocol: ExchangeProtocol,
    card_decoder: StreamDecoder,
}

impl NormalDeviceRuntime {
    fn open() -> Result<Self, CoreHostProcessError> {
        Ok(Self {
            display_file: inherited_file(DISPLAY_FD, false)?,
            keypad_file: inherited_file(KEYPAD_FD, true)?,
            card_response_file: inherited_file(CARD_RESPONSE_FD, true)?,
            card_request_file: inherited_file(CARD_REQUEST_FD, false)?,
            display_protocol: OneWayProtocol::new(Capability::Display),
            keypad_decoder: StreamDecoder::new(Capability::Keypad),
            card_protocol: ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse)
                .map_err(CoreHostProcessError::Device)?,
            card_decoder: StreamDecoder::new(Capability::CardResponse),
        })
    }

    fn read_card_profile(&mut self) -> Result<Profile, CoreHostProcessError> {
        let frame = self.card_exchange(MessageKind::CardReadProfile)?;
        match frame.parsed_body().map_err(CoreHostProcessError::Device)? {
            BodyRef::CardResponse(CardResponseBody::Profile(profile)) => Ok(profile),
            BodyRef::CardResponse(CardResponseBody::Rejected {
                request_kind,
                error,
            }) => Err(card_rejection(request_kind, error)),
            _ => Err(CoreHostProcessError::UnexpectedEvent),
        }
    }

    fn read_normal_factor(&mut self) -> Result<ReceivedFrame, CoreHostProcessError> {
        let frame = self.card_exchange(MessageKind::CardReadNormalFactor)?;
        match frame.parsed_body().map_err(CoreHostProcessError::Device)? {
            BodyRef::CardResponse(CardResponseBody::NormalFactor(_)) => Ok(frame),
            BodyRef::CardResponse(CardResponseBody::Rejected {
                request_kind,
                error,
            }) => Err(card_rejection(request_kind, error)),
            _ => Err(CoreHostProcessError::UnexpectedEvent),
        }
    }

    fn card_exchange(&mut self, kind: MessageKind) -> Result<ReceivedFrame, CoreHostProcessError> {
        let request = self
            .card_protocol
            .begin(kind)
            .map_err(CoreHostProcessError::Device)?;
        let mut bytes = WipingArray::<DEVICE_HEADER_BYTES>::zeroed();
        let length = request
            .encode(&[], bytes.as_mut_array())
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
        let rejected = matches!(
            frame.parsed_body().map_err(CoreHostProcessError::Device)?,
            BodyRef::CardResponse(CardResponseBody::Rejected { .. })
        );
        match self.card_protocol.accept_response(&frame) {
            Ok(()) => Ok(frame),
            Err(DeviceError::DeviceRejected) if rejected => Ok(frame),
            Err(error) => Err(CoreHostProcessError::Device(error)),
        }
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

fn card_rejection(kind: MessageKind, error: DeviceRejection) -> CoreHostProcessError {
    let request_kind = match kind {
        MessageKind::CardReadProfile => 0x01,
        MessageKind::CardReadNormalFactor => 0x02,
        _ => 0,
    };
    let status = match error {
        DeviceRejection::Absent => 0x0001,
        DeviceRejection::AccessRejected => 0x0002,
        DeviceRejection::Unavailable => 0x0003,
    };
    let mut controller = match NormalProcessControllerV2::start(b"01") {
        Ok(controller) => controller,
        Err(error) => return CoreHostProcessError::Normal(error),
    };
    CoreHostProcessError::Normal(controller.reject_card(request_kind, status))
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
    use super::{CoreHostProcessError, NormalDeviceRuntime};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::{NormalScreenV2, NormalStageV2};
    use qk_device_wire::{Capability, ExchangeProtocol, OneWayProtocol, StreamDecoder};
    use std::fs::{File, OpenOptions};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

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
        NormalDeviceRuntime {
            display_file,
            keypad_file: null_file(true),
            card_response_file: null_file(true),
            card_request_file,
            display_protocol: OneWayProtocol::new(Capability::Display),
            keypad_decoder: StreamDecoder::new(Capability::Keypad),
            card_protocol: ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse)
                .expect("card exchange protocol"),
            card_decoder: StreamDecoder::new(Capability::CardResponse),
        }
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
            runtime.card_exchange(qk_device_wire::MessageKind::CardReadProfile),
            Err(CoreHostProcessError::DeviceWriteFailed)
        ));
        assert_eq!(wiped_bytes(), qk_device_wire::HEADER_BYTES);
    }
}
