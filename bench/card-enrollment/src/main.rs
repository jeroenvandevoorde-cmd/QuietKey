#![forbid(unsafe_code)]

use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use qk_card_enrollment::{
    encode_transcript, run_enrollment, EnrollmentMetadata, EnrollmentMode, EnrollmentOutcome,
    EnrollmentRecord, PcscEnrollmentBackend,
};

fn usage() {
    eprintln!(
        "usage: qk-card-enrollment enumerate <source-commit> <utc> <host-alias> <reader-alias>"
    );
    eprintln!(
        "   or: qk-card-enrollment enroll <source-commit> <utc> <host-alias> <reader-alias> <specimen-alias> <selected-reader-name-lowerhex>"
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

fn parse_arguments() -> Option<EnrollmentMetadata> {
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
            Some(EnrollmentMetadata {
                mode: EnrollmentMode::Enumerate,
                source_commit,
                timestamp_utc,
                host_alias,
                reader_alias,
                specimen_alias: None,
                selected_reader_name: None,
            })
        }
        "enroll" => {
            let specimen_alias = arguments.next()?;
            let selected_reader_name = parse_lower_hex(&arguments.next()?)?;
            if arguments.next().is_some() {
                return None;
            }
            Some(EnrollmentMetadata {
                mode: EnrollmentMode::Enroll,
                source_commit,
                timestamp_utc,
                host_alias,
                reader_alias,
                specimen_alias: Some(specimen_alias),
                selected_reader_name: Some(selected_reader_name),
            })
        }
        _ => None,
    }
}

fn main() -> ExitCode {
    let Some(metadata) = parse_arguments() else {
        usage();
        return ExitCode::from(64);
    };
    let metadata = match metadata.validate() {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("result={}", error.name());
            return ExitCode::from(64);
        }
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
