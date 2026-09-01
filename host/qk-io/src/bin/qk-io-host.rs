#![forbid(unsafe_code)]

use qk_io::run_io_host_process;
use std::process::ExitCode;

const INVOCATION_REJECTED: u8 = 64;
const RUNTIME_TERMINATED: u8 = 70;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match std::panic::catch_unwind(run) {
        Ok(status) => status,
        Err(_) => ExitCode::from(RUNTIME_TERMINATED),
    }
}

fn run() -> ExitCode {
    if std::env::args_os().count() != 1 {
        return ExitCode::from(INVOCATION_REJECTED);
    }
    match run_io_host_process() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(RUNTIME_TERMINATED),
    }
}
