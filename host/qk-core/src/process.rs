//! Real HOST child boundary for the trusted qk-core process.

use crate::wipe;
use crate::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreReceiveEvent, CoreSession,
    Interruption, MockCardSlot, MockDisplay, MockKeypad,
};
use qk_ipc::{inherited_endpoint, receive_bytes_once, IpcError, UnixReceiveError};
use std::fmt;
use std::io::Write;
use std::os::unix::net::UnixStream;

const RECEIVE_BYTES: usize = 1;

/// Closed HOST child failure surface. No variant contains transported bytes,
/// wallet facts, a session identity, or another secret-bearing value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreHostProcessError {
    Endpoint(UnixReceiveError),
    Core(CoreError),
    WriteFailed,
    UnexpectedEvent,
    ConnectionClosed,
}

impl fmt::Display for CoreHostProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Core(error) => error.fmt(formatter),
            Self::WriteFailed => formatter.write_str("WriteFailed"),
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
    let mut scratch = [0u8; RECEIVE_BYTES];
    loop {
        let received = match receive_bytes_once(stream, &mut scratch) {
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
        let input = match scratch.get(..received) {
            Some(input) => input,
            None => {
                terminate_unexpected(session);
                return Err(CoreHostProcessError::UnexpectedEvent);
            }
        };
        let result = session.receive(input, false);
        wipe::bytes(&mut scratch);
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
