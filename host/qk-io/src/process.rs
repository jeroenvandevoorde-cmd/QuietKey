//! Real HOST child boundary for the no-secret qk-io broker process.

use crate::device_process::{DeviceProcess, DeviceProcessError};
use crate::wipe::WipingArray;
use crate::{BrokerError, BrokerSession, BrokerState, InnerError};
use qk_device_wire::DeviceError;
use qk_ipc::{
    inherited_endpoint, receive_once, IpcError, StreamDecoder, UnixReceiveError, UnixReceiveOutcome,
};
use std::fmt;
use std::io::Write;
use std::os::unix::net::UnixStream;

const RECEIVE_BYTES: usize = 1;

/// Closed no-secret broker-child failure surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoHostProcessError {
    Endpoint(UnixReceiveError),
    Broker(BrokerError),
    Device(DeviceError),
    Inner(InnerError),
    WriteFailed,
}

impl fmt::Display for IoHostProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Broker(error) => error.fmt(formatter),
            Self::Device(error) => error.fmt(formatter),
            Self::Inner(error) => error.fmt(formatter),
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
    let mut devices = DeviceProcess::new();
    let mut decoder = StreamDecoder::new();
    let mut scratch = WipingArray::<RECEIVE_BYTES>::zeroed();
    loop {
        let outcome = match receive_control_once(stream, &mut decoder, &mut scratch) {
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
        let reply = devices
            .accept(&mut broker, &frame)
            .map_err(|error| match error {
                DeviceProcessError::Broker(error) => IoHostProcessError::Broker(error),
                DeviceProcessError::Device(error) => IoHostProcessError::Device(error),
                DeviceProcessError::Inner(error) => IoHostProcessError::Inner(error),
            })?;
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

fn receive_control_once(
    stream: &UnixStream,
    decoder: &mut StreamDecoder,
    scratch: &mut WipingArray<RECEIVE_BYTES>,
) -> Result<UnixReceiveOutcome, UnixReceiveError> {
    let result = receive_once(stream, decoder, scratch.as_mut_slice());
    scratch.clear();
    result
}

fn latch_receive_failure(broker: &mut BrokerSession, error: IpcError) {
    if error == IpcError::PeerLost {
        let _ = broker.peer_lost();
    } else {
        let _ = broker.receive_failed(error);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{receive_control_once, StreamDecoder, UnixStream, WipingArray, RECEIVE_BYTES};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use std::io::Write;

    #[test]
    fn control_receive_clears_the_complete_scratch_on_success() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&[0x51]).unwrap();
        let mut decoder = StreamDecoder::new();
        let mut scratch = WipingArray::<RECEIVE_BYTES>::zeroed();
        reset_wiped_bytes();
        let outcome = receive_control_once(&stream, &mut decoder, &mut scratch).unwrap();
        assert_eq!(outcome.received(), RECEIVE_BYTES);
        assert_eq!(wiped_bytes(), RECEIVE_BYTES);
    }

    #[test]
    fn control_receive_clears_the_complete_scratch_on_peer_loss() {
        let (stream, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut decoder = StreamDecoder::new();
        let mut scratch = WipingArray::<RECEIVE_BYTES>::zeroed();
        reset_wiped_bytes();
        assert!(receive_control_once(&stream, &mut decoder, &mut scratch).is_err());
        assert_eq!(wiped_bytes(), RECEIVE_BYTES);
    }
}
