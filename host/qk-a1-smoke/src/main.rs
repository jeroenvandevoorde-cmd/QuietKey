//! Designated non-corpus M19 scrap-transcription smoke harness.
//!
//! HOST FIXTURE TOOL ONLY -- PUBLIC NEVER-FUND VALUES ONLY -- NOT A READER --
//! NO OCR OR IMAGE INPUT -- NOT A PRODUCTION DECODER -- NOT A WALLET.

#![deny(unsafe_code)]

use qk_a1::{decrypt, A1Error};
use qk_a1_codec::{decode, CodecError, CodecProfile, DecodeReport};
use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

const ERASURE_MARKER: u8 = b'?';
const MAX_SYMBOL_COUNT: usize = 128;

// Patterned public T0 fixture A2 from the QK-DEC-093 M18 fixture.
const T0_PUBLIC_A2: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];

// M11 GOLDEN NUMS-lineage wallet_id reused by the QK-DEC-093 fixture.
const GOLDEN_WALLET_ID: [u8; 32] = [
    0xa7, 0x98, 0x90, 0xdc, 0xde, 0x9c, 0x85, 0x17, 0xad, 0x86, 0x0a, 0xb3, 0xa9, 0x07, 0xff, 0x01,
    0x65, 0x2b, 0xbe, 0x20, 0x0a, 0x56, 0x10, 0x28, 0xce, 0xb6, 0x6e, 0x22, 0xe8, 0xc9, 0xd5, 0x43,
];

const T0_PUBLIC_NONCE: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
];

const T0_PUBLIC_SEED_A: [u8; 32] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

#[derive(Clone, Copy)]
struct ProfileSpec {
    profile: CodecProfile,
    name: &'static str,
    symbols: usize,
}

impl ProfileSpec {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "Rs72_60" => Some(Self {
                profile: CodecProfile::Rs72_60,
                name: "Rs72_60",
                symbols: 116,
            }),
            "Rs76_60" => Some(Self {
                profile: CodecProfile::Rs76_60,
                name: "Rs76_60",
                symbols: 122,
            }),
            "Rs80_60" => Some(Self {
                profile: CodecProfile::Rs80_60,
                name: "Rs80_60",
                symbols: 128,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum InputError {
    ReadFailed,
    EmbeddedLineBreak,
    InputTooLong,
    InvalidSymbolCount { expected: usize, actual: usize },
}

struct Transcription {
    bytes: [u8; MAX_SYMBOL_COUNT],
    len: usize,
}

struct Prepared {
    symbols: [u8; MAX_SYMBOL_COUNT],
    erasures: [u8; MAX_SYMBOL_COUNT],
    erasure_symbols: usize,
}

#[derive(Debug)]
enum SmokeFailure {
    Input(InputError),
    ReedSolomon {
        error: CodecError,
        erasure_symbols: usize,
    },
    Aead {
        error: A1Error,
        report: DecodeReport,
        erasure_symbols: usize,
    },
    UnexpectedFixture {
        report: DecodeReport,
        erasure_symbols: usize,
    },
}

struct SmokeSuccess {
    report: DecodeReport,
    erasure_symbols: usize,
}

fn read_transcription_from(reader: &mut impl Read) -> Result<Transcription, InputError> {
    let mut transcription = Transcription {
        bytes: [0u8; MAX_SYMBOL_COUNT],
        len: 0,
    };
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte).map_err(|_| InputError::ReadFailed)?;
        if read == 0 || byte[0] == b'\n' {
            return Ok(transcription);
        }
        if byte[0] == b'\r' {
            let following = reader.read(&mut byte).map_err(|_| InputError::ReadFailed)?;
            if following == 1 && byte[0] == b'\n' {
                return Ok(transcription);
            }
            return Err(InputError::EmbeddedLineBreak);
        }
        if transcription.len == MAX_SYMBOL_COUNT {
            return Err(InputError::InputTooLong);
        }
        transcription.bytes[transcription.len] = byte[0];
        transcription.len += 1;
    }
}

fn read_transcription() -> Result<Transcription, InputError> {
    read_transcription_from(&mut io::stdin().lock())
}

fn prepare(spec: ProfileSpec, transcription: &[u8]) -> Result<Prepared, InputError> {
    if transcription.len() != spec.symbols {
        return Err(InputError::InvalidSymbolCount {
            expected: spec.symbols,
            actual: transcription.len(),
        });
    }

    let mut prepared = Prepared {
        symbols: [b'2'; MAX_SYMBOL_COUNT],
        erasures: [0u8; MAX_SYMBOL_COUNT],
        erasure_symbols: 0,
    };
    for (position, byte) in transcription.iter().copied().enumerate() {
        if byte == ERASURE_MARKER {
            prepared.erasures[position] = 1;
            prepared.erasure_symbols += 1;
        } else {
            prepared.symbols[position] = byte;
        }
    }
    Ok(prepared)
}

fn smoke(spec: ProfileSpec, transcription: &[u8]) -> Result<SmokeSuccess, SmokeFailure> {
    let prepared = prepare(spec, transcription).map_err(SmokeFailure::Input)?;
    let mut capsule = [0u8; 67];
    let report = decode(
        spec.profile,
        &prepared.symbols[..spec.symbols],
        &prepared.erasures[..spec.symbols],
        &mut capsule,
    )
    .map_err(|error| SmokeFailure::ReedSolomon {
        error,
        erasure_symbols: prepared.erasure_symbols,
    })?;

    let mut seed_a = [0u8; 32];
    let authenticated = decrypt(&T0_PUBLIC_A2, &GOLDEN_WALLET_ID, &capsule, &mut seed_a);
    let exact_fixture = capsule[7..19] == T0_PUBLIC_NONCE && seed_a == T0_PUBLIC_SEED_A;
    capsule.fill(0);
    seed_a.fill(0);
    authenticated.map_err(|error| SmokeFailure::Aead {
        error,
        report,
        erasure_symbols: prepared.erasure_symbols,
    })?;
    if !exact_fixture {
        return Err(SmokeFailure::UnexpectedFixture {
            report,
            erasure_symbols: prepared.erasure_symbols,
        });
    }

    Ok(SmokeSuccess {
        report,
        erasure_symbols: prepared.erasure_symbols,
    })
}

fn print_header(spec: ProfileSpec, erasure_symbols: usize) {
    println!(
        "profile={} symbols={} erasure_symbols={}",
        spec.name, spec.symbols, erasure_symbols
    );
}

fn print_input_error(error: &InputError) {
    match error {
        InputError::ReadFailed => println!("input=FAIL error=ReadFailed"),
        InputError::EmbeddedLineBreak => println!("input=FAIL error=EmbeddedLineBreak"),
        InputError::InputTooLong => println!("input=FAIL error=InputTooLong"),
        InputError::InvalidSymbolCount { expected, actual } => println!(
            "input=FAIL error=InvalidSymbolCount expected={} actual={}",
            expected, actual
        ),
    }
    println!("rs=NOT_RUN");
    println!("aead=NOT_RUN");
    println!("fixture=NOT_RUN");
}

fn usage() {
    eprintln!("usage: qk-a1-smoke <Rs72_60|Rs76_60|Rs80_60>");
    eprintln!("stdin: type one exact line and press Enter; '?' is an erasure; no spaces or wrap");
}

fn main() -> ExitCode {
    let mut arguments = env::args();
    let _program = arguments.next();
    let Some(profile_argument) = arguments.next() else {
        usage();
        return ExitCode::from(64);
    };
    if arguments.next().is_some() {
        usage();
        return ExitCode::from(64);
    }
    let Some(spec) = ProfileSpec::parse(&profile_argument) else {
        usage();
        return ExitCode::from(64);
    };

    let transcription = match read_transcription() {
        Ok(value) => value,
        Err(error) => {
            print_input_error(&error);
            return ExitCode::from(1);
        }
    };

    match smoke(spec, &transcription.bytes[..transcription.len]) {
        Ok(success) => {
            print_header(spec, success.erasure_symbols);
            println!(
                "rs=PASS corrected_errors={} erased_bytes={}",
                success.report.corrected_errors, success.report.erased_bytes
            );
            println!("aead=PASS");
            println!("fixture=PASS");
            ExitCode::SUCCESS
        }
        Err(SmokeFailure::Input(error)) => {
            print_input_error(&error);
            ExitCode::from(1)
        }
        Err(SmokeFailure::ReedSolomon {
            error,
            erasure_symbols,
        }) => {
            print_header(spec, erasure_symbols);
            println!("rs=FAIL error={error:?}");
            println!("aead=NOT_RUN");
            println!("fixture=NOT_RUN");
            ExitCode::from(2)
        }
        Err(SmokeFailure::Aead {
            error,
            report,
            erasure_symbols,
        }) => {
            print_header(spec, erasure_symbols);
            println!(
                "rs=PASS corrected_errors={} erased_bytes={}",
                report.corrected_errors, report.erased_bytes
            );
            println!("aead=FAIL error={error:?}");
            println!("fixture=NOT_RUN");
            ExitCode::from(3)
        }
        Err(SmokeFailure::UnexpectedFixture {
            report,
            erasure_symbols,
        }) => {
            print_header(spec, erasure_symbols);
            println!(
                "rs=PASS corrected_errors={} erased_bytes={}",
                report.corrected_errors, report.erased_bytes
            );
            println!("aead=PASS");
            println!("fixture=FAIL error=UnexpectedT0Fixture");
            ExitCode::from(4)
        }
    }
}
