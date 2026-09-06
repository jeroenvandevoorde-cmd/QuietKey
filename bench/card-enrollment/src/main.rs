#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use qk_card_enrollment::{
    encode_transcript, execute_pcsc_identity, execute_pcsc_sitting, run_enrollment,
    EnrollmentMetadata, EnrollmentMode, EnrollmentOutcome, EnrollmentRecord, IdentityOutcome,
    PcscEnrollmentBackend, SittingError, SittingMetadata, SittingMode, SittingOutcome,
};

enum Command {
    Enrollment(EnrollmentMetadata),
    Identity(EnrollmentMetadata),
    Sitting {
        mode: SittingMode,
        metadata: EnrollmentMetadata,
        output_path: PathBuf,
    },
}

enum ArgumentError {
    Usage,
    Sitting(SittingError),
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
        "   or: qk-card-enrollment sitting <install-info|provision-golden> <source-commit> <utc> <host-alias> <reader-alias> <specimen-alias> <reader-name-lowerhex> <absolute-new-output>"
    );
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
    if mode == "sitting" {
        let sitting_mode = SittingMode::parse(&arguments.next().ok_or(ArgumentError::Usage)?)
            .map_err(ArgumentError::Sitting)?;
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
        return Ok(Command::Sitting {
            mode: sitting_mode,
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
        });
    }
    let source_commit = arguments.next().ok_or(ArgumentError::Usage)?;
    let timestamp_utc = arguments.next().ok_or(ArgumentError::Usage)?;
    let host_alias = arguments.next().ok_or(ArgumentError::Usage)?;
    let reader_alias = arguments.next().ok_or(ArgumentError::Usage)?;
    match mode.as_str() {
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
        Ok(command) => command,
        Err(ArgumentError::Usage) => {
            usage();
            return ExitCode::from(64);
        }
        Err(ArgumentError::Sitting(error)) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
    };
    match command {
        Command::Enrollment(metadata) => run_enrollment_command(metadata),
        Command::Identity(metadata) => run_identity_command(metadata),
        Command::Sitting {
            mode,
            metadata,
            output_path,
        } => run_sitting_command(mode, metadata, output_path),
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
