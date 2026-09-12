#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::ExitCode;

use qk_card_enrollment::{
    encode_transcript, execute_pcsc_b6, execute_pcsc_identity, execute_pcsc_interruption,
    execute_pcsc_management_observation, execute_pcsc_sitting, removal_wait_for, run_enrollment,
    B6Error, B6Metadata, B6Outcome, EnrollmentMetadata, EnrollmentMode, EnrollmentOutcome,
    EnrollmentRecord, IdentityOutcome, InterruptionError, InterruptionMetadata, InterruptionMode,
    InterruptionOutcome, InterruptionTrial, ManagementObservationMetadata, ObservationError,
    ObservationOutcome, PcscEnrollmentBackend, SittingError, SittingMetadata, SittingMode,
    SittingOutcome, REMOVAL_WAIT_ENV,
};

enum Command {
    Sec1210Readback(qk_card_enrollment::Sec1210ReadbackMetadata),
    Sec1210(qk_card_enrollment::Sec1210Metadata),
    Interruption {
        mode: InterruptionMode,
        trial: InterruptionTrial,
        metadata: EnrollmentMetadata,
        output_path: PathBuf,
    },
    Enrollment(EnrollmentMetadata),
    Identity(EnrollmentMetadata),
    ManagementObservation {
        metadata: EnrollmentMetadata,
        output_path: PathBuf,
    },
    Sitting {
        mode: SittingMode,
        metadata: EnrollmentMetadata,
        output_path: PathBuf,
    },
    B6 {
        metadata: EnrollmentMetadata,
        output_path: PathBuf,
    },
}

enum ArgumentError {
    Sec1210Readback(qk_card_enrollment::Sec1210ReadbackError),
    Sec1210(qk_card_enrollment::Sec1210Error),
    Usage,
    Sitting(SittingError),
    Interruption(InterruptionError),
}

fn usage() {
    eprintln!(
        "usage: qk-card-enrollment enumerate <source-commit> <utc> <host-alias> <reader-alias>"
    );
    eprintln!(
        "   or: qk-card-enrollment enroll <source-commit> <utc> <host-alias> <reader-alias> <specimen-alias> <selected-reader-name-lowerhex>"
    );
    eprintln!(
        "   or: qk-card-enrollment identity <source-commit> <utc> <host-alias> <reader-alias> <specimen-alias> <selected-reader-name-lowerhex>"
    );
    eprintln!(
        "   or: qk-card-enrollment sitting <install-info|provision-golden|committed-readback|management-observe> <source-commit> <utc> <host-alias> <reader-alias> <specimen-alias> <reader-name-lowerhex> <absolute-new-output>"
    );
    eprintln!(
        "   or: qk-card-enrollment b6 <campaign-source> <utc> <host-alias> <reader-alias> <specimen-alias> <reader-name-lowerhex> <absolute-new-output>"
    );
    eprintln!("   or: qk-card-enrollment sitting <interrupt-golden|classify-golden|abort-staging-golden> <trial-id> <campaign-source> <utc> <host-alias> <reader-alias> <specimen-alias> <reader-name-lowerhex> <absolute-new-output>");
    eprintln!("   or: qk-card-enrollment sec1210-probe <tool-source-commit> <UTC> RIG-HOST-PI3B-01 J3R180-03 <absolute-new-output>");
    eprintln!("   or: qk-card-enrollment sec1210-readback <tool-source-commit> <UTC> RIG-HOST-PI3B-01 J3R180-03 <absolute-new-output>");
}

fn parse_lower_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| -> u8 {
                match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => unreachable!("validated lowercase hex"),
                }
            };
            Some((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn parse_arguments() -> Result<Command, ArgumentError> {
    let mut arguments = env::args();
    let _program = arguments.next().ok_or(ArgumentError::Usage)?;
    let mode = arguments.next().ok_or(ArgumentError::Usage)?;
    if mode == "sec1210-readback" {
        let source = arguments.next().ok_or(ArgumentError::Usage)?;
        let utc = arguments.next().ok_or(ArgumentError::Usage)?;
        let host = arguments.next().ok_or(ArgumentError::Usage)?;
        let specimen = arguments.next().ok_or(ArgumentError::Usage)?;
        let output = PathBuf::from(arguments.next().ok_or(ArgumentError::Usage)?);
        if arguments.next().is_some() {
            return Err(ArgumentError::Usage);
        }
        return qk_card_enrollment::Sec1210ReadbackMetadata::new(
            source, utc, &host, &specimen, output,
        )
        .map(Command::Sec1210Readback)
        .map_err(ArgumentError::Sec1210Readback);
    }
    if mode == "sec1210-probe" {
        let source = arguments.next().ok_or(ArgumentError::Usage)?;
        let utc = arguments.next().ok_or(ArgumentError::Usage)?;
        let host = arguments.next().ok_or(ArgumentError::Usage)?;
        let specimen = arguments.next().ok_or(ArgumentError::Usage)?;
        let output = PathBuf::from(arguments.next().ok_or(ArgumentError::Usage)?);
        if arguments.next().is_some() {
            return Err(ArgumentError::Usage);
        }
        return qk_card_enrollment::Sec1210Metadata::new(source, utc, &host, &specimen, output)
            .map(Command::Sec1210)
            .map_err(ArgumentError::Sec1210);
    }
    if mode == "sitting" {
        let sitting_name = arguments.next().ok_or(ArgumentError::Usage)?;
        let interruption_mode = InterruptionMode::parse(&sitting_name).ok();
        let trial = if interruption_mode.is_some() {
            Some(
                InterruptionTrial::parse(&arguments.next().ok_or(ArgumentError::Usage)?)
                    .map_err(ArgumentError::Interruption)?,
            )
        } else {
            None
        };
        let sitting_mode = if sitting_name == "management-observe" || interruption_mode.is_some() {
            None
        } else {
            Some(SittingMode::parse(&sitting_name).map_err(ArgumentError::Sitting)?)
        };
        let source_commit = arguments.next().ok_or(ArgumentError::Usage)?;
        let timestamp_utc = arguments.next().ok_or(ArgumentError::Usage)?;
        let host_alias = arguments.next().ok_or(ArgumentError::Usage)?;
        let reader_alias = arguments.next().ok_or(ArgumentError::Usage)?;
        let specimen_alias = arguments.next().ok_or(ArgumentError::Usage)?;
        let selected_reader_name = parse_lower_hex(&arguments.next().ok_or(ArgumentError::Usage)?)
            .ok_or(ArgumentError::Usage)?;
        let output_path = PathBuf::from(arguments.next().ok_or(ArgumentError::Usage)?);
        if arguments.next().is_some() {
            return Err(ArgumentError::Usage);
        }
        let metadata = EnrollmentMetadata {
            mode: EnrollmentMode::Enroll,
            source_commit,
            timestamp_utc,
            host_alias,
            reader_alias,
            specimen_alias: Some(specimen_alias),
            selected_reader_name: Some(selected_reader_name),
        };
        if let (Some(mode), Some(trial)) = (interruption_mode, trial) {
            return Ok(Command::Interruption {
                mode,
                trial,
                metadata,
                output_path,
            });
        }
        return Ok(match sitting_mode {
            Some(mode) => Command::Sitting {
                mode,
                metadata,
                output_path,
            },
            None => Command::ManagementObservation {
                metadata,
                output_path,
            },
        });
    }
    let source_commit = arguments.next().ok_or(ArgumentError::Usage)?;
    let timestamp_utc = arguments.next().ok_or(ArgumentError::Usage)?;
    let host_alias = arguments.next().ok_or(ArgumentError::Usage)?;
    let reader_alias = arguments.next().ok_or(ArgumentError::Usage)?;
    match mode.as_str() {
        "b6" => {
            let specimen_alias = arguments.next().ok_or(ArgumentError::Usage)?;
            let selected_reader_name =
                parse_lower_hex(&arguments.next().ok_or(ArgumentError::Usage)?)
                    .ok_or(ArgumentError::Usage)?;
            let output_path = PathBuf::from(arguments.next().ok_or(ArgumentError::Usage)?);
            if arguments.next().is_some() {
                return Err(ArgumentError::Usage);
            }
            Ok(Command::B6 {
                metadata: EnrollmentMetadata {
                    mode: EnrollmentMode::Enroll,
                    source_commit,
                    timestamp_utc,
                    host_alias,
                    reader_alias,
                    specimen_alias: Some(specimen_alias),
                    selected_reader_name: Some(selected_reader_name),
                },
                output_path,
            })
        }
        "enumerate" => {
            if arguments.next().is_some() {
                return Err(ArgumentError::Usage);
            }
            Ok(Command::Enrollment(EnrollmentMetadata {
                mode: EnrollmentMode::Enumerate,
                source_commit,
                timestamp_utc,
                host_alias,
                reader_alias,
                specimen_alias: None,
                selected_reader_name: None,
            }))
        }
        "enroll" | "identity" => {
            let specimen_alias = arguments.next().ok_or(ArgumentError::Usage)?;
            let selected_reader_name =
                parse_lower_hex(&arguments.next().ok_or(ArgumentError::Usage)?)
                    .ok_or(ArgumentError::Usage)?;
            if arguments.next().is_some() {
                return Err(ArgumentError::Usage);
            }
            let metadata = EnrollmentMetadata {
                mode: EnrollmentMode::Enroll,
                source_commit,
                timestamp_utc,
                host_alias,
                reader_alias,
                specimen_alias: Some(specimen_alias),
                selected_reader_name: Some(selected_reader_name),
            };
            if mode == "identity" {
                Ok(Command::Identity(metadata))
            } else {
                Ok(Command::Enrollment(metadata))
            }
        }
        _ => Err(ArgumentError::Usage),
    }
}

fn main() -> ExitCode {
    let command = match parse_arguments() {
        Err(ArgumentError::Sec1210Readback(error)) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
        Err(ArgumentError::Sec1210(error)) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
        Ok(command) => command,
        Err(ArgumentError::Usage) => {
            usage();
            return ExitCode::from(64);
        }
        Err(ArgumentError::Sitting(error)) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
        Err(ArgumentError::Interruption(error)) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
    };
    match command {
        Command::Sec1210Readback(metadata) => {
            std::panic::set_hook(Box::new(|_| {}));
            let result = catch_unwind(AssertUnwindSafe(|| {
                qk_card_enrollment::execute_sec1210_readback(metadata)
            }))
            .unwrap_or(Err(
                qk_card_enrollment::Sec1210Error::BoundaryPanicked.into()
            ));
            let failure = match result {
                Ok(summary) => summary.failure,
                Err(e) => Some(e),
            };
            if let Some(e) = failure {
                eprintln!("result={}", e.name());
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Command::Sec1210(metadata) => {
            std::panic::set_hook(Box::new(|_| {}));
            let result = catch_unwind(AssertUnwindSafe(|| {
                qk_card_enrollment::execute_sec1210_probe(metadata)
            }))
            .unwrap_or(Err(qk_card_enrollment::Sec1210Error::BoundaryPanicked));
            let failure = match result {
                Ok(summary) => summary.failure,
                Err(error) => Some(error),
            };
            if let Some(error) = failure {
                eprintln!("result={}", error.name());
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Command::Interruption {
            mode,
            trial,
            metadata,
            output_path,
        } => run_interruption_command(mode, trial, metadata, output_path),
        Command::Enrollment(metadata) => run_enrollment_command(metadata),
        Command::Identity(metadata) => run_identity_command(metadata),
        Command::ManagementObservation {
            metadata,
            output_path,
        } => run_management_observation_command(metadata, output_path),
        Command::Sitting {
            mode,
            metadata,
            output_path,
        } => run_sitting_command(mode, metadata, output_path),
        Command::B6 {
            metadata,
            output_path,
        } => run_b6_command(metadata, output_path),
    }
}

fn run_interruption_command(
    mode: InterruptionMode,
    trial: InterruptionTrial,
    metadata: EnrollmentMetadata,
    output_path: PathBuf,
) -> ExitCode {
    let metadata = match validate_metadata(metadata) {
        Ok(m) => m,
        Err(exit) => return exit,
    };
    let metadata = match removal_wait_for(mode, trial, || env::var_os(REMOVAL_WAIT_ENV))
        .and_then(|wait| InterruptionMetadata::new(mode, trial, metadata, output_path, wait))
    {
        Ok(m) => m,
        Err(error) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
    };
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| execute_pcsc_interruption(metadata)))
        .unwrap_or(Err(SittingError::SittingBoundaryPanicked.into()));
    match result {
        Ok(InterruptionOutcome::Reject(error)) | Err(error) => {
            eprintln!("result={}", error.name());
            ExitCode::from(1)
        }
        Ok(_) => ExitCode::SUCCESS,
    }
}

fn run_b6_command(metadata: EnrollmentMetadata, output_path: PathBuf) -> ExitCode {
    let metadata = match validate_metadata(metadata) {
        Ok(metadata) => metadata,
        Err(exit) => return exit,
    };
    let metadata = match B6Metadata::new(metadata, output_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
    };
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| execute_pcsc_b6(metadata)))
        .unwrap_or(Err(B6Error::B6BoundaryPanicked));
    match result {
        Ok(B6Outcome::Pass) => ExitCode::SUCCESS,
        Ok(B6Outcome::Reject(error)) | Err(error) => {
            eprintln!("result={}", error.name());
            ExitCode::from(1)
        }
    }
}

fn run_management_observation_command(
    metadata: EnrollmentMetadata,
    output_path: PathBuf,
) -> ExitCode {
    let metadata = match validate_metadata(metadata) {
        Ok(metadata) => metadata,
        Err(exit) => return exit,
    };
    let metadata = match ManagementObservationMetadata::new(metadata, output_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
    };
    // This mode never sends panic payloads or private observations to the console.
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(|| {
        execute_pcsc_management_observation(metadata)
    }))
    .unwrap_or(Err(ObservationError::Sitting(
        SittingError::SittingBoundaryPanicked,
    )));
    match result {
        Ok(ObservationOutcome::Pass) => ExitCode::SUCCESS,
        Ok(ObservationOutcome::Reject(error)) | Err(error) => {
            eprintln!("result={}", error.name());
            ExitCode::from(1)
        }
    }
}

fn run_sitting_command(
    mode: SittingMode,
    metadata: EnrollmentMetadata,
    output_path: PathBuf,
) -> ExitCode {
    let metadata = match validate_metadata(metadata) {
        Ok(metadata) => metadata,
        Err(exit) => return exit,
    };
    let metadata = match SittingMetadata::new(mode, metadata, output_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
    };
    match execute_pcsc_sitting(metadata) {
        Ok(SittingOutcome::Pass) => ExitCode::SUCCESS,
        Ok(SittingOutcome::Reject(error)) | Err(error) => {
            eprintln!("result={}", error.name());
            ExitCode::from(1)
        }
    }
}

fn validate_metadata(
    metadata: EnrollmentMetadata,
) -> Result<qk_card_enrollment::ValidatedMetadata, ExitCode> {
    metadata.validate().map_err(|error| {
        eprintln!("result={}", error.name());
        ExitCode::from(64)
    })
}

fn run_enrollment_command(metadata: EnrollmentMetadata) -> ExitCode {
    let metadata = match validate_metadata(metadata) {
        Ok(metadata) => metadata,
        Err(exit) => return exit,
    };
    let mut backend = match PcscEnrollmentBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            return write_record(EnrollmentRecord {
                metadata,
                readers: Vec::new(),
                events: Vec::new(),
                observed_atr: None,
                observed_protocol: None,
                capture: None,
                outcome: EnrollmentOutcome::Reject(error),
            });
        }
    };
    let record = run_enrollment(metadata, &mut backend);
    write_record(record)
}

fn run_identity_command(metadata: EnrollmentMetadata) -> ExitCode {
    let metadata = match validate_metadata(metadata) {
        Ok(metadata) => metadata,
        Err(exit) => return exit,
    };
    match execute_pcsc_identity(metadata) {
        Ok((transcript, outcome)) => write_identity_execution(&transcript, outcome),
        Err(error) => {
            eprintln!("result={}", error.name());
            ExitCode::from(1)
        }
    }
}

fn write_record(record: EnrollmentRecord) -> ExitCode {
    let transcript = match encode_transcript(&record) {
        Ok(transcript) => transcript,
        Err(error) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(1);
        }
    };
    if io::stdout().lock().write_all(&transcript).is_err() {
        eprintln!("result=OutputFailed");
        return ExitCode::from(1);
    }
    match record.outcome {
        EnrollmentOutcome::Pass => ExitCode::SUCCESS,
        EnrollmentOutcome::Reject(_) => ExitCode::from(1),
    }
}

fn write_identity_execution(transcript: &[u8], outcome: IdentityOutcome) -> ExitCode {
    if io::stdout().lock().write_all(transcript).is_err() {
        eprintln!("result=OutputFailed");
        return ExitCode::from(1);
    }
    match outcome {
        IdentityOutcome::Pass => ExitCode::SUCCESS,
        IdentityOutcome::Reject(_) => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_lower_hex;

    #[test]
    fn selected_reader_hex_is_canonical() {
        assert_eq!(parse_lower_hex("0041ff"), Some(vec![0x00, 0x41, 0xff]));
        assert_eq!(parse_lower_hex(""), None);
        assert_eq!(parse_lower_hex("0"), None);
        assert_eq!(parse_lower_hex("AA"), None);
        assert_eq!(parse_lower_hex("xz"), None);
    }
}
