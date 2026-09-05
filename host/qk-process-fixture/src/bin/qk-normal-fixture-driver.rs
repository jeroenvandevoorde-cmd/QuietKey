#![deny(unsafe_code)]

#[path = "../card_scenario_v1.rs"]
mod card_scenario_v1;
#[path = "../main.rs"]
mod common;
#[path = "../scenario.rs"]
mod scenario;
#[path = "../wipe.rs"]
#[allow(unsafe_code)]
mod wipe;

use std::process::ExitCode;

const INVOCATION_REJECTED: u8 = 64;
const FIXTURE_FAILED: u8 = 70;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match std::panic::catch_unwind(run) {
        Ok(status) => status,
        Err(_) => ExitCode::from(FIXTURE_FAILED),
    }
}

fn run() -> ExitCode {
    let spec = match common::parse_driver_arguments(std::env::args_os().skip(1)) {
        Ok(spec) => spec,
        Err(_) => return ExitCode::from(INVOCATION_REJECTED),
    };
    match scenario::run_driver(spec) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(FIXTURE_FAILED),
    }
}
