//! Private Linux UART adapter. No generic command sender is exported.
use crate::{
    run_sec1210, Sec1210Error, Sec1210Metadata, Sec1210Summary, Sec1210Transcript, Sec1210Transport,
};
use std::fs::{File, OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Default)]
struct Uart {
    stream: Option<File>,
    #[cfg(target_os = "linux")]
    sent_at: Option<std::time::Instant>,
}

impl Sec1210Transport for Uart {
    fn configure(&mut self) -> Result<i32, Sec1210Error> {
        #[cfg(target_os = "linux")]
        {
            use std::process::{Command, Stdio};
            let status = Command::new("stty")
                .args(crate::SEC1210_STTY_ARGS)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|_| Sec1210Error::SttyUnavailable)?;
            Ok(status.code().unwrap_or(-1))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Sec1210Error::UnsupportedPlatform)
        }
    }
    fn open(&mut self) -> Result<(), Sec1210Error> {
        #[cfg(target_os = "linux")]
        {
            // Linux O_NOCTTY; std owns the descriptor and sets close-on-exec.
            let stream = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(0x100)
                .open(crate::SEC1210_TTY)
                .map_err(|_| Sec1210Error::OpenFailed)?;
            self.stream = Some(stream);
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Sec1210Error::UnsupportedPlatform)
        }
    }
    fn write_once(&mut self, request: &[u8]) -> Result<usize, Sec1210Error> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            let count = self
                .stream
                .as_mut()
                .ok_or(Sec1210Error::OpenFailed)?
                .write(request)
                .map_err(|_| Sec1210Error::WriteFailed)?;
            self.sent_at = Some(std::time::Instant::now());
            Ok(count)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(Sec1210Error::UnsupportedPlatform)
        }
    }
    fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
        std::thread::sleep(std::time::Duration::from_millis(10));
        Ok(())
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            let started = self.sent_at.ok_or(Sec1210Error::ReadFailed)?;
            let elapsed = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if elapsed() >= 5000 {
                return Ok((0, elapsed()));
            }
            let count = self
                .stream
                .as_mut()
                .ok_or(Sec1210Error::OpenFailed)?
                .read(buffer)
                .map_err(|_| Sec1210Error::ReadFailed)?;
            Ok((count, elapsed()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buffer;
            Err(Sec1210Error::UnsupportedPlatform)
        }
    }
    fn release(&mut self) -> Result<bool, Sec1210Error> {
        let existed = self.stream.is_some();
        drop(self.stream.take());
        Ok(existed)
    }
}

pub fn execute_sec1210_probe(metadata: Sec1210Metadata) -> Result<Sec1210Summary, Sec1210Error> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(metadata.output())
        .map_err(|_| Sec1210Error::OutputCreateFailed)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| Sec1210Error::OutputCreateFailed)?;
    if file
        .metadata()
        .map_err(|_| Sec1210Error::OutputCreateFailed)?
        .permissions()
        .mode()
        & 0o777
        != 0o600
    {
        return Err(Sec1210Error::OutputCreateFailed);
    }
    let mut transcript = Sec1210Transcript::new(file);
    let mut uart = Uart::default();
    Ok(run_sec1210(&metadata, &mut uart, &mut transcript))
}
