//! Private PC/SC boundary for QK-DEC-165-SUP-001's four fixed observations.

use std::ffi::CString;
use std::fs::{File, OpenOptions, Permissions};
use std::mem;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use pcsc::{Context, Disposition, Protocol, Protocols, Scope, ShareMode};

use crate::management_observation::MAX_OBSERVATION_RESPONSE_BYTES;
use crate::{
    run_management_observation, ManagementObservationBackend, ManagementObservationMetadata,
    ManagementObservationTranscript, NegotiatedProtocol, ObservationError, ObservationOutcome,
    ObservationStatus, SittingError, SittingTransportFailure, MAX_ATR_BYTES, MAX_READERS,
    MAX_READER_LIST_BYTES, MAX_READER_NAME_BYTES, SITTING_READER_NAME,
};

const _: [(); MAX_ATR_BYTES] = [(); pcsc::MAX_ATR_SIZE];

pub fn execute_pcsc_management_observation(
    metadata: ManagementObservationMetadata,
) -> Result<ObservationOutcome, ObservationError> {
    // File creation and the engine's flushed header precede even context establishment.
    let file = open_observation_output(metadata.output_path())?;
    let mut transcript = ManagementObservationTranscript::new(file);
    let mut backend = PcscManagementObservationBackend::default();
    Ok(run_management_observation(&metadata, &mut backend, &mut transcript).outcome)
}

#[derive(Default)]
struct PcscManagementObservationBackend {
    context: Option<Context>,
    card: Option<pcsc::Card>,
}

impl ManagementObservationBackend for PcscManagementObservationBackend {
    fn establish_context(&mut self) -> Result<(), SittingError> {
        if self.context.is_some() || self.card.is_some() {
            return Err(SittingError::SittingSequenceViolation);
        }
        self.context = Some(
            Context::establish(Scope::User).map_err(|_| SittingError::SittingContextUnavailable)?,
        );
        Ok(())
    }

    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, SittingError> {
        let context = self
            .context
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?;
        let mut buffer = [0u8; MAX_READER_LIST_BYTES];
        let readers = context
            .list_readers(&mut buffer)
            .map_err(|error| match error {
                pcsc::Error::InsufficientBuffer => SittingError::SittingReaderListTooLarge,
                _ => SittingError::SittingReaderEnumerationFailed,
            })?;
        let mut result = Vec::new();
        for reader in readers {
            if result.len() == MAX_READERS {
                return Err(SittingError::SittingReaderCountExceeded);
            }
            let bytes = reader.to_bytes();
            if bytes.is_empty() || bytes.len() > MAX_READER_NAME_BYTES || bytes.contains(&0) {
                return Err(SittingError::SittingReaderNameRejected);
            }
            result.push(bytes.to_vec());
        }
        Ok(result)
    }

    fn connect_exclusive(&mut self, reader: &[u8]) -> Result<(), SittingError> {
        if self.card.is_some() || reader != SITTING_READER_NAME {
            return Err(SittingError::SittingSequenceViolation);
        }
        let context = self
            .context
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?;
        let reader = CString::new(reader).map_err(|_| SittingError::SittingReaderNameRejected)?;
        self.card = Some(
            context
                .connect(&reader, ShareMode::Exclusive, Protocols::ANY)
                .map_err(|_| SittingError::SittingConnectFailed)?,
        );
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.card.is_some()
    }

    fn reset(&mut self) -> Result<(), SittingError> {
        self.card
            .as_mut()
            .ok_or(SittingError::SittingSequenceViolation)?
            .reconnect(ShareMode::Exclusive, Protocols::ANY, Disposition::ResetCard)
            .map_err(|_| SittingError::SittingResetFailed)
    }

    fn capture_status(&mut self) -> Result<ObservationStatus, SittingError> {
        let card = self
            .card
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?;
        let mut names = [0u8; MAX_READER_LIST_BYTES];
        let mut atr = [0u8; MAX_ATR_BYTES];
        let status = card
            .status2(&mut names, &mut atr)
            .map_err(|_| SittingError::SittingStatusFailed)?;
        Ok(ObservationStatus {
            atr: status.atr().to_vec(),
            protocol: status.protocol2().map(|protocol| match protocol {
                Protocol::T0 => NegotiatedProtocol::T0,
                Protocol::T1 => NegotiatedProtocol::T1,
                Protocol::RAW => NegotiatedProtocol::Raw,
            }),
        })
    }

    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_OBSERVATION_RESPONSE_BYTES],
    ) -> Result<usize, SittingTransportFailure> {
        let card = self.card.as_ref().ok_or(SittingTransportFailure::Failed)?;
        // This private type is never exported; the engine supplies only its fixed table.
        card.transmit(request, response)
            .map(|bytes| bytes.len())
            .map_err(|error| match error {
                pcsc::Error::InsufficientBuffer => SittingTransportFailure::CaptureExceeded,
                _ => SittingTransportFailure::Failed,
            })
    }

    fn disconnect_leave_card(&mut self) -> Result<(), SittingError> {
        let card = self
            .card
            .take()
            .ok_or(SittingError::SittingSequenceViolation)?;
        match card.disconnect(Disposition::LeaveCard) {
            Ok(()) => Ok(()),
            Err((card, _)) => {
                // A returned Card must not perform pcsc's implicit ResetCard on drop.
                mem::forget(card);
                Err(SittingError::SittingDisconnectFailed)
            }
        }
    }
}

impl Drop for PcscManagementObservationBackend {
    fn drop(&mut self) {
        if self.card.is_some() {
            // Fallback for an unwind outside the engine's caught call boundaries.
            // The normal finish path has already consumed the card, even on failure.
            let _ = catch_unwind(AssertUnwindSafe(|| self.disconnect_leave_card()));
        }
    }
}

fn open_observation_output(path: &Path) -> Result<File, ObservationError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| SittingError::SittingOutputCreateFailed)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| SittingError::SittingOutputCreateFailed)?;
    if file
        .metadata()
        .map_err(|_| SittingError::SittingOutputCreateFailed)?
        .permissions()
        .mode()
        & 0o777
        != 0o600
    {
        return Err(SittingError::SittingOutputCreateFailed.into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn output_is_private_create_new_and_refuses_existing_file_or_link() {
        let directory = std::env::temp_dir().join(format!(
            "qk-management-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let output = directory.join("record.txt");
        let mut file = open_observation_output(&output).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        file.write_all(b"preserved\n").unwrap();
        file.flush().unwrap();
        drop(file);
        assert!(matches!(
            open_observation_output(&output),
            Err(ObservationError::Sitting(
                SittingError::SittingOutputCreateFailed
            ))
        ));
        assert_eq!(fs::read(&output).unwrap(), b"preserved\n");
        let link = directory.join("link.txt");
        symlink(&output, &link).unwrap();
        assert!(matches!(
            open_observation_output(&link),
            Err(ObservationError::Sitting(
                SittingError::SittingOutputCreateFailed
            ))
        ));
        assert_eq!(fs::read(&output).unwrap(), b"preserved\n");
        fs::remove_file(&link).unwrap();
        fs::remove_file(&output).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
