#![forbid(unsafe_code)]

use qk_supervisor::{parse_launcher_arguments, run_host_launcher};
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
    let invocation = match parse_launcher_arguments(std::env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        Err(_) => return ExitCode::from(INVOCATION_REJECTED),
    };
    match run_host_launcher(invocation.mode(), invocation.runtime_directory()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(RUNTIME_TERMINATED),
    }
}
