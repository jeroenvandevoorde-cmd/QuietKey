#![forbid(unsafe_code)]

use qk_core::{run_core_host_process, run_normal_core_host_process, CoreMode};
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
    let first = arguments.next();
    let second = arguments.next();
    let trailing = arguments.next();
    if trailing.is_some() {
        return ExitCode::from(INVOCATION_REJECTED);
    }
    let result = match (first.and_then(|value| value.into_string().ok()), second) {
        (Some(mode), None) if mode == "setup" => run_core_host_process(CoreMode::Setup),
        (Some(mode), None) if mode == "kit" => run_core_host_process(CoreMode::Kit),
        (Some(mode), Some(profile)) if mode == "normal" => {
            let Some(profile) = profile.to_str() else {
                return ExitCode::from(INVOCATION_REJECTED);
            };
            if !matches!(profile, "01" | "02" | "03") {
                return ExitCode::from(INVOCATION_REJECTED);
            }
            run_normal_core_host_process(profile.as_bytes())
        }
        _ => return ExitCode::from(INVOCATION_REJECTED),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(RUNTIME_TERMINATED),
    }
}
