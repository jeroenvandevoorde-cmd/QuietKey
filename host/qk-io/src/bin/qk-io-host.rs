#![forbid(unsafe_code)]

use qk_io::run_io_host_process;
use std::process::ExitCode;

const INVOCATION_REJECTED: u8 = 64;
const RUNTIME_TERMINATED: u8 = 70;

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        return ExitCode::from(INVOCATION_REJECTED);
    }
    match run_io_host_process() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(RUNTIME_TERMINATED),
    }
}
