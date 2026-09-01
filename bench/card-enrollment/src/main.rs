#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use qk_card_enrollment::{
    encode_identity_transcript, encode_transcript, run_enrollment, run_identity,
    EnrollmentMetadata, EnrollmentMode, EnrollmentOutcome, EnrollmentRecord, IdentityExchange,
    IdentityOutcome, IdentityRecord, PcscEnrollmentBackend, PcscIdentityBackend,
};

enum Command {
    Enrollment(EnrollmentMetadata),
    Identity(EnrollmentMetadata),
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

fn parse_arguments() -> Option<Command> {
    let mut arguments = env::args();
    let _program = arguments.next()?;
    let mode = arguments.next()?;
    let source_commit = arguments.next()?;
    let timestamp_utc = arguments.next()?;
    let host_alias = arguments.next()?;
    let reader_alias = arguments.next()?;
    match mode.as_str() {
        "enumerate" => {
            if arguments.next().is_some() {
                return None;
            }
            Some(Command::Enrollment(EnrollmentMetadata {
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
            let specimen_alias = arguments.next()?;
            let selected_reader_name = parse_lower_hex(&arguments.next()?)?;
            if arguments.next().is_some() {
                return None;
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
                Some(Command::Identity(metadata))
            } else {
                Some(Command::Enrollment(metadata))
            }
        }
        _ => None,
    }
}

fn main() -> ExitCode {
    let Some(command) = parse_arguments() else {
        usage();
        return ExitCode::from(64);
    };
    match command {
        Command::Enrollment(metadata) => run_enrollment_command(metadata),
        Command::Identity(metadata) => run_identity_command(metadata),
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
    let mut backend = match PcscIdentityBackend::new() {
        Ok(backend) => backend,
        Err(error) => {
            return write_identity_record(IdentityRecord {
                metadata,
                readers: Vec::new(),
                events: Vec::new(),
                observed_atr: None,
                observed_protocol: None,
                exchanges: core::array::from_fn(|_| IdentityExchange::default()),
                disconnected: None,
                outcome: IdentityOutcome::Reject(error),
            });
        }
    };
    let record = run_identity(metadata, &mut backend);
    write_identity_record(record)
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

fn write_identity_record(record: IdentityRecord) -> ExitCode {
    let transcript = match encode_identity_transcript(&record) {
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
