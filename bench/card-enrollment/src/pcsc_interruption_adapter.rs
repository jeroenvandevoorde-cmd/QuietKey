//! Private bounded PC/SC boundary for the compiled interruption plans.

use std::ffi::CString;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::mem;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Duration;

use crate::interruption::ClearOnDrop;
use crate::{
    run_interruption, InterruptionBackend, InterruptionError, InterruptionMetadata,
    InterruptionOutcome, InterruptionTranscript, NegotiatedProtocol, ObservationStatus,
    RemovalWaitMs, SittingError, MAX_ATR_BYTES, MAX_READERS, MAX_READER_LIST_BYTES,
    MAX_READER_NAME_BYTES, MAX_SITTING_CAPTURE_BYTES, SITTING_READER_NAME,
};
use pcsc::{Context, Disposition, Protocol, Protocols, ReaderState, Scope, ShareMode, State};

pub fn execute_pcsc_interruption(
    metadata: InterruptionMetadata,
) -> Result<InterruptionOutcome, InterruptionError> {
    let output = open_interruption_output(metadata.output_path())?;
    let mut transcript = InterruptionTranscript::new(output);
    let mut backend = PcscInterruptionBackend {
        context: None,
        card: None,
        prepare_removal: metadata.needs_removal_wait(),
        reader_state: None,
    };
    Ok(run_interruption(&metadata, &mut backend, &mut transcript).outcome)
}

struct PcscInterruptionBackend {
    context: Option<Context>,
    card: Option<pcsc::Card>,
    prepare_removal: bool,
    reader_state: Option<ReaderState>,
}
impl PcscInterruptionBackend {
    fn disconnect(&mut self, disposition: Disposition) -> Result<(), InterruptionError> {
        let card = self
            .card
            .take()
            .ok_or(SittingError::SittingSequenceViolation)?;
        match card.disconnect(disposition) {
            Ok(()) => Ok(()),
            Err((card, error)) => {
                mem::forget(card);
                Err(InterruptionError::Native(error))
            }
        }
    }
}
impl InterruptionBackend for PcscInterruptionBackend {
    fn establish_context(&mut self) -> Result<(), InterruptionError> {
        if self.context.is_some() {
            return Err(SittingError::SittingSequenceViolation.into());
        }
        self.context = Some(Context::establish(Scope::User).map_err(InterruptionError::Native)?);
        Ok(())
    }
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, InterruptionError> {
        let context = self
            .context
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?;
        let mut buffer = [0u8; MAX_READER_LIST_BYTES];
        let buffer = ClearOnDrop(&mut buffer);
        let readers = context
            .list_readers(buffer.0)
            .map_err(InterruptionError::Native)?;
        let mut result = Vec::new();
        for reader in readers {
            if result.len() == MAX_READERS {
                return Err(SittingError::SittingReaderCountExceeded.into());
            }
            let name = reader.to_bytes();
            if name.is_empty() || name.len() > MAX_READER_NAME_BYTES {
                return Err(SittingError::SittingReaderNameRejected.into());
            }
            result.push(name.to_vec());
        }
        Ok(result)
    }
    fn connect_exclusive(&mut self) -> Result<(), InterruptionError> {
        if self.card.is_some() {
            return Err(SittingError::SittingSequenceViolation.into());
        }
        let name = CString::new(SITTING_READER_NAME)
            .map_err(|_| SittingError::SittingReaderNameRejected)?;
        self.card = Some(
            self.context
                .as_ref()
                .ok_or(SittingError::SittingSequenceViolation)?
                .connect(&name, ShareMode::Exclusive, Protocols::T1)
                .map_err(InterruptionError::Native)?,
        );
        Ok(())
    }
    fn is_connected(&self) -> bool {
        self.card.is_some()
    }
    fn capture_status(&mut self) -> Result<ObservationStatus, InterruptionError> {
        let mut names = [0; MAX_READER_LIST_BYTES];
        let names = ClearOnDrop(&mut names);
        let mut atr = [0; MAX_ATR_BYTES];
        let atr = ClearOnDrop(&mut atr);
        let status = self
            .card
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?
            .status2(names.0, atr.0)
            .map_err(InterruptionError::Native)?;
        let observation = ObservationStatus {
            atr: status.atr().to_vec(),
            protocol: status.protocol2().map(|p| match p {
                Protocol::T0 => NegotiatedProtocol::T0,
                Protocol::T1 => NegotiatedProtocol::T1,
                Protocol::RAW => NegotiatedProtocol::Raw,
            }),
        };
        if self.prepare_removal {
            let name = CString::new(SITTING_READER_NAME)
                .map_err(|_| SittingError::SittingReaderNameRejected)?;
            let mut states = [ReaderState::new(name, State::UNAWARE)];
            self.context
                .as_ref()
                .ok_or(SittingError::SittingSequenceViolation)?
                .get_status_change(Some(Duration::ZERO), &mut states)
                .map_err(InterruptionError::Native)?;
            let state = states[0].event_state();
            if !state.contains(State::PRESENT)
                || state.intersects(State::EMPTY | State::UNKNOWN | State::UNAVAILABLE)
            {
                return Err(InterruptionError::ReaderStateRejected);
            }
            states[0].sync_current_state();
            self.reader_state = Some(
                states
                    .into_iter()
                    .next()
                    .ok_or(InterruptionError::ReaderStateRejected)?,
            );
        }
        Ok(observation)
    }
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_SITTING_CAPTURE_BYTES],
    ) -> Result<usize, InterruptionError> {
        self.card
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?
            .transmit(request, response)
            .map(|bytes| bytes.len())
            .map_err(InterruptionError::Native)
    }
    fn unpower(&mut self) -> Result<(), InterruptionError> {
        self.disconnect(Disposition::UnpowerCard)
    }
    fn signal_removal(&mut self) -> Result<(), InterruptionError> {
        let mut stderr = io::stderr().lock();
        stderr
            .write_all(b"REMOVE_CARD_AT_COMMIT_DISPATCH\n")
            .and_then(|()| stderr.flush())
            .map_err(|_| SittingError::SittingOutputWriteFailed.into())
    }
    fn wait_removal(&mut self, timeout: RemovalWaitMs) -> Result<State, InterruptionError> {
        let state = self
            .reader_state
            .take()
            .ok_or(InterruptionError::ReaderStateRejected)?;
        let mut states = [state];
        self.context
            .as_ref()
            .ok_or(SittingError::SittingSequenceViolation)?
            .get_status_change(
                Some(Duration::from_millis(u64::from(timeout.get()))),
                &mut states,
            )
            .map_err(|error| {
                if error == pcsc::Error::Timeout {
                    InterruptionError::RemovalWaitTimedOut
                } else {
                    InterruptionError::Native(error)
                }
            })?;
        Ok(states[0].event_state())
    }
    fn disconnect_leave_card(&mut self) -> Result<(), InterruptionError> {
        self.disconnect(Disposition::LeaveCard)
    }
}
impl Drop for PcscInterruptionBackend {
    fn drop(&mut self) {
        if self.card.is_some() {
            let _ = catch_unwind(AssertUnwindSafe(|| self.disconnect_leave_card()));
        }
    }
}

fn open_interruption_output(path: &Path) -> Result<File, InterruptionError> {
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
    #[test]
    fn private_output_never_overwrites_existing_file_or_symlink() {
        let root =
            std::env::temp_dir().join(format!("qk-interruption-output-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("output.txt");
        let mut file = open_interruption_output(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        file.write_all(b"preserved").unwrap();
        drop(file);
        assert!(open_interruption_output(&path).is_err());
        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(open_interruption_output(&link).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"preserved");
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
