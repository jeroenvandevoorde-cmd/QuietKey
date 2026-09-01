//! Real HOST child boundary for the no-secret qk-io broker process.

use crate::{BrokerError, BrokerSession, BrokerState};
use qk_ipc::{inherited_endpoint, receive_once, IpcError, StreamDecoder, UnixReceiveError};
use std::fmt;
use std::io::Write;
use std::os::unix::net::UnixStream;

const RECEIVE_BYTES: usize = 1;

/// Closed no-secret broker-child failure surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoHostProcessError {
    Endpoint(UnixReceiveError),
    Broker(BrokerError),
    WriteFailed,
}

impl fmt::Display for IoHostProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Broker(error) => error.fmt(formatter),
            Self::WriteFailed => formatter.write_str("WriteFailed"),
        }
    }
}

impl std::error::Error for IoHostProcessError {}

/// Run the existing QKIP broker until one clean SessionClosed or one failure.
/// No input or output mock is injected, so this slice opens no operation path.
pub fn run_io_host_process() -> Result<(), IoHostProcessError> {
    let stream = inherited_endpoint().map_err(IoHostProcessError::Endpoint)?;
    run_control_peer(&stream)
}

fn run_control_peer(stream: &UnixStream) -> Result<(), IoHostProcessError> {
    let mut broker = BrokerSession::new();
    let mut decoder = StreamDecoder::new();
    let mut scratch = [0u8; RECEIVE_BYTES];
    loop {
        let outcome = match receive_once(stream, &mut decoder, &mut scratch) {
            Ok(outcome) => outcome,
            Err(UnixReceiveError::Ipc(error)) => {
                latch_receive_failure(&mut broker, error);
                return Err(IoHostProcessError::Endpoint(UnixReceiveError::Ipc(error)));
            }
            Err(error) => {
                let _ = broker.peer_lost();
                return Err(IoHostProcessError::Endpoint(error));
            }
        };
        if !outcome.frame_ready() {
            continue;
        }
        let frame = decoder
            .take_frame()
            .map_err(|error| IoHostProcessError::Broker(broker.receive_failed(error)))?;
        let reply = broker
            .accept(&frame, None, None)
            .map_err(IoHostProcessError::Broker)?;
        let mut writer = stream;
        if writer.write_all(reply.frame_bytes()).is_err() {
            let _ = broker.peer_lost();
            return Err(IoHostProcessError::WriteFailed);
        }
        if broker.state() == BrokerState::Closed {
            return Ok(());
        }
    }
}

fn latch_receive_failure(broker: &mut BrokerSession, error: IpcError) {
    if error == IpcError::PeerLost {
        let _ = broker.peer_lost();
    } else {
        let _ = broker.receive_failed(error);
    }
}
