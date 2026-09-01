#![forbid(unsafe_code)]

use qk_decoy::DecoyHostProcess;
use std::process::ExitCode;

const INVOCATION_REJECTED: u8 = 64;

fn main() -> ExitCode {
    if std::env::args_os().count() != 1 {
        return ExitCode::from(INVOCATION_REJECTED);
    }
    DecoyHostProcess::new().wait()
}
