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

// A separate invocation-wide clock leaves probe clock semantics unchanged.
struct ReadbackUart {
    uart: Uart,
    epoch: std::time::Instant,
}
impl Sec1210Transport for ReadbackUart {
    fn configure(&mut self) -> Result<i32, Sec1210Error> {
        self.uart.configure()
    }
    fn open(&mut self) -> Result<(), Sec1210Error> {
        self.uart.open()
    }
    fn write_once(&mut self, request: &[u8]) -> Result<usize, Sec1210Error> {
        self.uart.write_once(request)
    }
    fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
        self.uart.pause_after_write()
    }
    fn read(&mut self, buffer: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
        self.uart.read(buffer)
    }
    fn release(&mut self) -> Result<bool, Sec1210Error> {
        self.uart.release()
    }
}
impl crate::Sec1210ReadbackTransport for ReadbackUart {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

pub fn execute_sec1210_readback(
    metadata: crate::Sec1210ReadbackMetadata,
) -> Result<crate::Sec1210ReadbackSummary, crate::Sec1210ReadbackError> {
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
        return Err(Sec1210Error::OutputCreateFailed.into());
    }
    let mut transcript = crate::Sec1210ReadbackTranscript::new(file);
    let mut uart = ReadbackUart {
        uart: Uart::default(),
        epoch: std::time::Instant::now(),
    };
    Ok(crate::run_sec1210_readback(
        &metadata,
        &mut uart,
        &mut transcript,
    ))
}

pub fn execute_sec1210_ifs_readback(
    metadata: crate::Sec1210IfsReadbackMetadata,
) -> Result<crate::Sec1210IfsReadbackSummary, crate::Sec1210IfsReadbackError> {
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
        return Err(Sec1210Error::OutputCreateFailed.into());
    }
    let mut transcript = crate::Sec1210IfsReadbackTranscript::new(file);
    let mut uart = ReadbackUart {
        uart: Uart::default(),
        epoch: std::time::Instant::now(),
    };
    Ok(crate::run_sec1210_ifs_readback(
        &metadata,
        &mut uart,
        &mut transcript,
    ))
}

pub fn execute_sec1210_fidi_readback(
    metadata: crate::Sec1210FidiReadbackMetadata,
) -> Result<crate::Sec1210FidiReadbackSummary, crate::Sec1210FidiReadbackError> {
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
        return Err(Sec1210Error::OutputCreateFailed.into());
    }
    let mut transcript = crate::Sec1210FidiReadbackTranscript::new(file);
    let mut uart = ReadbackUart {
        uart: Uart::default(),
        epoch: std::time::Instant::now(),
    };
    Ok(crate::run_sec1210_fidi_readback(
        &metadata,
        &mut uart,
        &mut transcript,
    ))
}

// The SIGN lane alone accepts an absolute per-command deadline, including WTX.
// Every earlier adapter byte and the sole native write site remain unchanged.
struct SignUart {
    uart: Uart,
    epoch: std::time::Instant,
}
impl Sec1210Transport for SignUart {
    fn configure(&mut self) -> Result<i32, Sec1210Error> {
        self.uart.configure()
    }
    fn open(&mut self) -> Result<(), Sec1210Error> {
        self.uart.open()
    }
    fn write_once(&mut self, request: &[u8]) -> Result<usize, Sec1210Error> {
        self.uart.write_once(request)
    }
    fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
        self.uart.pause_after_write()
    }
    fn read(&mut self, _: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
        Err(Sec1210Error::ReadFailed)
    }
    fn release(&mut self) -> Result<bool, Sec1210Error> {
        self.uart.release()
    }
}
impl crate::Sec1210FidiSignTransport for SignUart {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn utc_now(&mut self) -> Result<String, crate::Sec1210FidiSignError> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| crate::B6Error::B6ClockFailed)?
            .as_secs();
        sign_utc_second(seconds).ok_or(crate::B6Error::B6ClockFailed.into())
    }
    fn read_until(
        &mut self,
        buffer: &mut [u8],
        deadline_ms: u64,
    ) -> Result<(usize, u64), Sec1210Error> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            let started = self.uart.sent_at.ok_or(Sec1210Error::ReadFailed)?;
            let elapsed = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if self.now_ms() >= deadline_ms {
                return Ok((0, elapsed()));
            }
            // The unchanged stty VTIME bounds each read to half a second.
            // Unlike the old path, this does not truncate a WTX budget at 5 s.
            let count = self
                .uart
                .stream
                .as_mut()
                .ok_or(Sec1210Error::OpenFailed)?
                .read(buffer)
                .map_err(|_| Sec1210Error::ReadFailed)?;
            Ok((count, elapsed()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (buffer, deadline_ms);
            Err(Sec1210Error::UnsupportedPlatform)
        }
    }
}

fn sign_utc_second(seconds: u64) -> Option<String> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let second_of_day = seconds % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(1970..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

pub fn execute_sec1210_fidi_sign(
    metadata: crate::Sec1210FidiSignMetadata,
) -> Result<crate::Sec1210FidiSignSummary, crate::Sec1210FidiSignError> {
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
        return Err(Sec1210Error::OutputCreateFailed.into());
    }
    let mut transcript = crate::Sec1210FidiSignTranscript::new(file);
    let mut uart = SignUart {
        uart: Uart::default(),
        epoch: std::time::Instant::now(),
    };
    Ok(crate::run_sec1210_fidi_sign(
        &metadata,
        &mut uart,
        &mut transcript,
    ))
}

#[cfg(test)]
mod sign_clock_tests {
    #[test]
    fn sign_utc_bounds_and_leap_day() {
        assert_eq!(
            super::sign_utc_second(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            super::sign_utc_second(951_827_696).as_deref(),
            Some("2000-02-29T12:34:56Z")
        );
        assert_eq!(
            super::sign_utc_second(253_402_300_799).as_deref(),
            Some("9999-12-31T23:59:59Z")
        );
        assert_eq!(super::sign_utc_second(253_402_300_800), None);
    }
}
