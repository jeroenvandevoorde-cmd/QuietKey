#![forbid(unsafe_code)]

use qk_core::{run_core_host_process, CoreMode};
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
    let mut arguments = std::env::args_os();
    let _ = arguments.next();
    let mode = match (arguments.next(), arguments.next()) {
        (Some(argument), None) => match argument.to_str() {
            Some("setup") => CoreMode::Setup,
            Some("normal") => CoreMode::A1B,
            Some("kit") => CoreMode::Kit,
            _ => return ExitCode::from(INVOCATION_REJECTED),
        },
        _ => return ExitCode::from(INVOCATION_REJECTED),
    };
    match run_core_host_process(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(RUNTIME_TERMINATED),
    }
}
