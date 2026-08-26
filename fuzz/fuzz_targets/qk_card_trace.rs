#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_card_trace::{inspect_trace, TraceError, TraceLimits, TraceMode};

const PRESENTED_FILENAME: &str =
    "qk-card-trace-v1__MOCK-F8G0-D-001__MOCK-J3R180-001__20260825T120000Z.txt";
static OVERSIZE_TRACE: [u8; 4097] = [0; 4097];

fn assert_named_error(error: TraceError) {
    match error {
        TraceError::InvalidHarnessLimit
        | TraceError::InputTooLarge
        | TraceError::EmptyInput
        | TraceError::NonAscii
        | TraceError::CarriageReturn
        | TraceError::MissingFinalLf
        | TraceError::InvalidMagic
        | TraceError::InvalidHeader
        | TraceError::InvalidIdentifier
        | TraceError::InvalidTimestamp
        | TraceError::InvalidMode
        | TraceError::LiveModeNotAuthorized
        | TraceError::UnsupportedAllowlist
        | TraceError::InvalidDigest
        | TraceError::InvalidRecordCount
        | TraceError::TooManyRecords
        | TraceError::InvalidRecord
        | TraceError::InvalidSequence
        | TraceError::NonMonotonicTime
        | TraceError::InvalidHex
        | TraceError::RecordTooLarge
        | TraceError::AtrMustBeFirst
        | TraceError::DuplicateAtr
        | TraceError::InvalidAtrLength
        | TraceError::ProtocolBeforeAtr
        | TraceError::ProtocolMissing
        | TraceError::ApduRecordNotAuthorized
        | TraceError::RecordCountMismatch
        | TraceError::MockIdentityMismatch
        | TraceError::FilenameMismatch => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = TraceLimits::new(4096, 16, 64, 32, 33).expect("fixed nonzero harness limits");
    match inspect_trace(data, PRESENTED_FILENAME, limits) {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(inspect_trace(data, PRESENTED_FILENAME, limits), Err(error));
        }
        Ok(summary) => {
            assert_eq!(summary.mode, TraceMode::Mock);
            assert_eq!(summary.expected_filename, PRESENTED_FILENAME);
            assert_eq!(summary.atr_records, 1);
            assert!(summary.protocol_records >= 1);
            assert_eq!(summary.apdu_commands, 0);
            assert_eq!(summary.apdu_responses, 0);
            assert_eq!(
                summary.records,
                summary.atr_records + summary.protocol_records
            );

            let reparsed = inspect_trace(data, PRESENTED_FILENAME, limits)
                .expect("accepted trace must deterministically reparse");
            assert_eq!(reparsed, summary);
        }
    }

    assert_eq!(
        TraceLimits::new(0, 16, 64, 32, 33),
        Err(TraceError::InvalidHarnessLimit)
    );
    assert_eq!(
        inspect_trace(&OVERSIZE_TRACE, PRESENTED_FILENAME, limits),
        Err(TraceError::InputTooLarge)
    );
});
