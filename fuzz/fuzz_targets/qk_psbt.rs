#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_psbt::{canonical_serialize, limits, parse, InputSource, RejectCategory, SerializeError};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
static QR_OVERSIZE: [u8; limits::MAX_QR_INPUT_BYTES + 1] = [0; limits::MAX_QR_INPUT_BYTES + 1];
static SD_OVERSIZE: [u8; limits::MAX_SD_INPUT_BYTES + 1] = [0; limits::MAX_SD_INPUT_BYTES + 1];

fn reject_name(category: RejectCategory) -> &'static str {
    match category {
        RejectCategory::InputTooLarge => "InputTooLarge",
        RejectCategory::InvalidMagic => "InvalidMagic",
        RejectCategory::Truncated => "Truncated",
        RejectCategory::NonMinimalCompactSize => "NonMinimalCompactSize",
        RejectCategory::InvalidKeyStructure => "InvalidKeyStructure",
        RejectCategory::InvalidValueStructure => "InvalidValueStructure",
        RejectCategory::DuplicateKey => "DuplicateKey",
        RejectCategory::V2GlobalField => "V2GlobalField",
        RejectCategory::TaprootField => "TaprootField",
        RejectCategory::MissingUnsignedTx => "MissingUnsignedTx",
        RejectCategory::MalformedUnsignedTx => "MalformedUnsignedTx",
        RejectCategory::UnsignedTxWitnessFormat => "UnsignedTxWitnessFormat",
        RejectCategory::UnsignedTxScriptSigNotEmpty => "UnsignedTxScriptSigNotEmpty",
        RejectCategory::UnsignedTxZeroInputs => "UnsignedTxZeroInputs",
        RejectCategory::UnsignedTxZeroOutputs => "UnsignedTxZeroOutputs",
        RejectCategory::InvalidMapCount => "InvalidMapCount",
        RejectCategory::TrailingBytes => "TrailingBytes",
        RejectCategory::TooManyInputs => "TooManyInputs",
        RejectCategory::TooManyOutputs => "TooManyOutputs",
        RejectCategory::TooManySigners => "TooManySigners",
        RejectCategory::PathTooDeep => "PathTooDeep",
        RejectCategory::AllocationFailed => "AllocationFailed",
        RejectCategory::UnsupportedPsbtVersion => "UnsupportedPsbtVersion",
        RejectCategory::KeyTooLong => "KeyTooLong",
        RejectCategory::ValueTooLong => "ValueTooLong",
        RejectCategory::TooManyRecords => "TooManyRecords",
        RejectCategory::TxOutputScriptTooLong => "TxOutputScriptTooLong",
    }
}

fn exercise(data: &[u8], source: InputSource) {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    let view = match parse(data, source) {
        Ok(view) => view,
        Err(error) => {
            assert!(error.offset <= data.len());
            assert!(!reject_name(error.category).is_empty());
            assert_eq!(parse(data, source).unwrap_err(), error);
            return;
        }
    };

    assert_eq!(view.buffer(), data);
    assert_eq!(view.source(), source);
    assert_eq!(view.input_map_count(), view.unsigned_tx().input_count);
    assert_eq!(view.output_map_count(), view.unsigned_tx().output_count);
    assert!(!view.unsigned_tx_bytes().is_empty());

    let canonical = match canonical_serialize(&view) {
        Ok(canonical) => canonical,
        Err(SerializeError::AllocationFailed) => return,
        Err(SerializeError::InvariantViolation) => {
            panic!("accepted PSBT violated a serializer invariant")
        }
    };
    assert_eq!(canonical.len(), data.len());

    let reparsed = match parse(&canonical, source) {
        Ok(view) => view,
        Err(error) => {
            let name = reject_name(error.category);
            panic!("canonical PSBT rejected as {name} at {}", error.offset);
        }
    };
    assert_eq!(reparsed.input_map_count(), view.input_map_count());
    assert_eq!(reparsed.output_map_count(), view.output_map_count());
    assert_eq!(reparsed.unsigned_tx_bytes(), view.unsigned_tx_bytes());

    match canonical_serialize(&reparsed) {
        Ok(second) => assert_eq!(second, canonical),
        Err(SerializeError::AllocationFailed) => {}
        Err(SerializeError::InvariantViolation) => {
            panic!("reparsed canonical PSBT violated a serializer invariant")
        }
    }
}

fn exercise_source_caps() {
    for (input, source) in [
        (QR_OVERSIZE.as_slice(), InputSource::Qr),
        (SD_OVERSIZE.as_slice(), InputSource::MicroSd),
    ] {
        let error = parse(input, source).expect_err("one byte over the source cap must reject");
        assert_eq!(error.category, RejectCategory::InputTooLarge);
        assert_eq!(error.offset, source.max_bytes());
        assert_eq!(parse(input, source).unwrap_err(), error);
    }
}

fn minimal_psbt() -> Vec<u8> {
    let mut transaction = vec![2, 0, 0, 0, 1];
    transaction.extend_from_slice(&[0; 32]);
    transaction.extend_from_slice(&[0; 4]);
    transaction.push(0);
    transaction.extend_from_slice(&[0xff; 4]);
    transaction.push(1);
    transaction.extend_from_slice(&[0; 8]);
    transaction.extend_from_slice(&[1, 0x51]);
    transaction.extend_from_slice(&[0; 4]);
    assert_eq!(transaction.len(), 61);

    let mut psbt = b"psbt\xff".to_vec();
    psbt.extend_from_slice(&[1, 0, transaction.len() as u8]);
    psbt.extend_from_slice(&transaction);
    psbt.extend_from_slice(&[0, 0, 0]);
    assert_eq!(psbt.len(), 72);
    psbt
}

fuzz_target!(|data: &[u8]| {
    exercise(data, InputSource::MicroSd);
    exercise(data, InputSource::Qr);
    exercise(&minimal_psbt(), InputSource::MicroSd);
    exercise_source_caps();
});
