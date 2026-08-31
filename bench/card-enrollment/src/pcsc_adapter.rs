//! Bounded adapter over the reviewed safe `pcsc` wrapper.

use std::ffi::CString;
use std::panic::{catch_unwind, AssertUnwindSafe};

use pcsc::{Context, Disposition, Protocol, Protocols, Scope, ShareMode};

use crate::{
    CaptureAttempt, CardCapture, EnrollmentBackend, EnrollmentError, NegotiatedProtocol,
    MAX_ATR_BYTES, MAX_READER_LIST_BYTES,
};

const _: [(); MAX_ATR_BYTES] = [(); pcsc::MAX_ATR_SIZE];

pub struct PcscEnrollmentBackend {
    context: Context,
}

impl PcscEnrollmentBackend {
    pub fn new() -> Result<Self, EnrollmentError> {
        match catch_unwind(|| Context::establish(Scope::User)) {
            Ok(Ok(context)) => Ok(Self { context }),
            Ok(Err(_)) => Err(EnrollmentError::ContextUnavailable),
            Err(_) => Err(EnrollmentError::BoundaryPanicked),
        }
    }
}

impl EnrollmentBackend for PcscEnrollmentBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, EnrollmentError> {
        let mut buffer = [0u8; MAX_READER_LIST_BYTES];
        match catch_unwind(AssertUnwindSafe(|| {
            self.context
                .list_readers(&mut buffer)
                .map(|readers| readers.map(|reader| reader.to_bytes().to_vec()).collect())
        })) {
            Ok(Ok(readers)) => Ok(readers),
            Ok(Err(pcsc::Error::InsufficientBuffer)) => Err(EnrollmentError::ReaderListTooLarge),
            Ok(Err(_)) => Err(EnrollmentError::ReaderEnumerationFailed),
            Err(_) => Err(EnrollmentError::BoundaryPanicked),
        }
    }

    fn capture_card(&mut self, reader_name: &[u8]) -> CaptureAttempt {
        let reader = match CString::new(reader_name) {
            Ok(reader) => reader,
            Err(_) => return CaptureAttempt::ConnectFailed,
        };
        let mut card = match catch_unwind(AssertUnwindSafe(|| {
            self.context
                .connect(&reader, ShareMode::Exclusive, Protocols::ANY)
        })) {
            Ok(Ok(card)) => card,
            Ok(Err(_)) => return CaptureAttempt::ConnectFailed,
            Err(_) => return CaptureAttempt::BoundaryPanicked,
        };

        match catch_unwind(AssertUnwindSafe(|| {
            card.reconnect(ShareMode::Exclusive, Protocols::ANY, Disposition::ResetCard)
        })) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                let _ = card.disconnect(Disposition::LeaveCard);
                return CaptureAttempt::ResetFailed;
            }
            Err(_) => {
                let _ = card.disconnect(Disposition::LeaveCard);
                return CaptureAttempt::BoundaryPanicked;
            }
        }

        let mut names_buffer = [0u8; MAX_READER_LIST_BYTES];
        let mut atr_buffer = [0u8; MAX_ATR_BYTES];
        let (atr, protocol) = match catch_unwind(AssertUnwindSafe(|| {
            card.status2(&mut names_buffer, &mut atr_buffer)
                .map(|status| (status.atr().to_vec(), status.protocol2()))
        })) {
            Ok(Ok(observation)) => observation,
            Ok(Err(_)) => {
                let _ = card.disconnect(Disposition::LeaveCard);
                return CaptureAttempt::StatusFailed;
            }
            Err(_) => {
                let _ = card.disconnect(Disposition::LeaveCard);
                return CaptureAttempt::BoundaryPanicked;
            }
        };
        let Some(protocol) = protocol else {
            let _ = card.disconnect(Disposition::LeaveCard);
            return CaptureAttempt::ProtocolUnavailable { atr };
        };
        let protocol = match protocol {
            Protocol::T0 => NegotiatedProtocol::T0,
            Protocol::T1 => NegotiatedProtocol::T1,
            Protocol::RAW => NegotiatedProtocol::Raw,
        };
        let capture = CardCapture { atr, protocol };

        match card.disconnect(Disposition::LeaveCard) {
            Ok(()) => CaptureAttempt::Success(capture),
            Err((_card, _)) => CaptureAttempt::DisconnectFailed(capture),
        }
    }
}
