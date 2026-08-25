//! Offline qk-card-trace command wrapper.

use qk_card_trace::{format_sha256, inspect_trace, TraceLimits};
use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

fn usage() {
    eprintln!(
        "usage: qk-card-trace <canonical-filename> <max-trace-bytes> <max-records> <max-record-bytes> <max-identifier-bytes> <max-atr-bytes>"
    );
    eprintln!("stdin: one complete canonical QK-CARD-TRACE-V1 text artifact");
}

fn positive_usize(value: &str) -> Option<usize> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok().filter(|number| *number > 0)
}

fn main() -> ExitCode {
    let mut arguments = env::args();
    let _program = arguments.next();
    let Some(filename) = arguments.next() else {
        usage();
        return ExitCode::from(64);
    };
    let Some(max_trace_bytes) = arguments.next().and_then(|value| positive_usize(&value)) else {
        usage();
        return ExitCode::from(64);
    };
    let Some(max_records) = arguments.next().and_then(|value| positive_usize(&value)) else {
        usage();
        return ExitCode::from(64);
    };
    let Some(max_record_bytes) = arguments.next().and_then(|value| positive_usize(&value)) else {
        usage();
        return ExitCode::from(64);
    };
    let Some(max_identifier_bytes) = arguments.next().and_then(|value| positive_usize(&value))
    else {
        usage();
        return ExitCode::from(64);
    };
    let Some(max_atr_bytes) = arguments.next().and_then(|value| positive_usize(&value)) else {
        usage();
        return ExitCode::from(64);
    };
    if arguments.next().is_some() {
        usage();
        return ExitCode::from(64);
    }
    let limits = TraceLimits::new(
        max_trace_bytes,
        max_records,
        max_record_bytes,
        max_identifier_bytes,
        max_atr_bytes,
    )
    .expect("positive arguments make valid harness controls");

    let mut input = Vec::new();
    let take_limit = u64::try_from(max_trace_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    if io::stdin()
        .lock()
        .take(take_limit)
        .read_to_end(&mut input)
        .is_err()
    {
        println!("trace=FAIL error=ReadFailed");
        return ExitCode::from(1);
    }
    match inspect_trace(&input, &filename, limits) {
        Ok(summary) => {
            println!(
                "trace=PASS mode=MOCK records={} atr={} protocol={} apdu_tx={} apdu_rx={}",
                summary.records,
                summary.atr_records,
                summary.protocol_records,
                summary.apdu_commands,
                summary.apdu_responses
            );
            println!("filename={}", summary.expected_filename);
            let digest = format_sha256(&summary.raw_artifact_sha256);
            println!(
                "raw_sha256={}",
                core::str::from_utf8(&digest).expect("hex is ASCII")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("trace=FAIL error={error:?}");
            ExitCode::from(1)
        }
    }
}
