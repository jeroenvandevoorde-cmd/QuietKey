//! Private fixed-sequence adapter for QK-F8-IDENT-V1.

use std::ffi::CString;
use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};

use pcsc::{Context, Disposition, Protocol, Protocols, Scope, ShareMode};

use crate::{
    encode_identity_transcript, run_identity, validate_card_recognition_response,
    validate_cplc_response, IdentityAttempt, IdentityBackend, IdentityError, IdentityExchange,
    IdentityOperation, IdentityOutcome, IdentityRecord, NegotiatedProtocol, ValidatedMetadata,
    CARD_RECOGNITION_COMMAND, CPLC_COMMAND, MAX_ATR_BYTES, MAX_IDENTITY_RESPONSE_BYTES,
    MAX_READER_LIST_BYTES, REGISTERED_J3R180_ATR,
};

const _: [(); MAX_ATR_BYTES] = [(); pcsc::MAX_ATR_SIZE];

struct PcscIdentityBackend {
    context: Context,
}

impl PcscIdentityBackend {
    fn new() -> Result<Self, IdentityError> {
        match catch_unwind(|| Context::establish(Scope::User)) {
            Ok(Ok(context)) => Ok(Self { context }),
            Ok(Err(_)) => Err(IdentityError::ContextUnavailable),
            Err(_) => Err(IdentityError::BoundaryPanicked),
        }
    }
}

pub fn execute_pcsc_identity(
    metadata: ValidatedMetadata,
) -> Result<(Vec<u8>, IdentityOutcome), IdentityError> {
    let record = match PcscIdentityBackend::new() {
        Ok(mut backend) => run_identity(metadata, &mut backend),
        Err(error) => IdentityRecord {
            metadata,
            readers: Vec::new(),
            events: Vec::new(),
            observed_atr: None,
            observed_protocol: None,
            exchanges: core::array::from_fn(|_| IdentityExchange::default()),
            disconnected: None,
            outcome: IdentityOutcome::Reject(error),
        },
    };
    let outcome = record.outcome;
    encode_identity_transcript(&record).map(|transcript| (transcript, outcome))
}

impl IdentityBackend for PcscIdentityBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, IdentityError> {
        let mut buffer = [0u8; MAX_READER_LIST_BYTES];
        match catch_unwind(AssertUnwindSafe(|| {
            self.context
                .list_readers(&mut buffer)
                .map(|readers| readers.map(|reader| reader.to_bytes().to_vec()).collect())
        })) {
            Ok(Ok(readers)) => Ok(readers),
            Ok(Err(pcsc::Error::InsufficientBuffer)) => Err(IdentityError::ReaderListTooLarge),
            Ok(Err(_)) => Err(IdentityError::ReaderEnumerationFailed),
            Err(_) => Err(IdentityError::BoundaryPanicked),
        }
    }

    fn capture_identity(&mut self, reader_name: &[u8]) -> IdentityAttempt {
        let mut attempt = IdentityAttempt::new();
        let reader = match CString::new(reader_name) {
            Ok(reader) => reader,
            Err(_) => {
                attempt.reject(
                    IdentityOperation::ExclusiveConnect,
                    IdentityError::ConnectFailed,
                );
                return attempt;
            }
        };
        let mut card = match catch_unwind(AssertUnwindSafe(|| {
            self.context
                .connect(&reader, ShareMode::Exclusive, Protocols::ANY)
        })) {
            Ok(Ok(card)) => card,
            Ok(Err(_)) => {
                attempt.reject(
                    IdentityOperation::ExclusiveConnect,
                    IdentityError::ConnectFailed,
                );
                return attempt;
            }
            Err(_) => {
                attempt.reject(
                    IdentityOperation::ExclusiveConnect,
                    IdentityError::BoundaryPanicked,
                );
                return attempt;
            }
        };
        attempt.push_pass(IdentityOperation::ExclusiveConnect);

        match catch_unwind(AssertUnwindSafe(|| {
            card.reconnect(ShareMode::Exclusive, Protocols::ANY, Disposition::ResetCard)
        })) {
            Ok(Ok(())) => attempt.push_pass(IdentityOperation::Reset),
            Ok(Err(_)) => {
                attempt.reject(IdentityOperation::Reset, IdentityError::ResetFailed);
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
            Err(_) => {
                attempt.reject(IdentityOperation::Reset, IdentityError::BoundaryPanicked);
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
        }

        let mut names_buffer = [0u8; MAX_READER_LIST_BYTES];
        let mut atr_buffer = [0u8; MAX_ATR_BYTES];
        let (atr, protocol) = match catch_unwind(AssertUnwindSafe(|| {
            card.status2(&mut names_buffer, &mut atr_buffer)
                .map(|status| (status.atr().to_vec(), status.protocol2()))
        })) {
            Ok(Ok(observation)) => observation,
            Ok(Err(_)) => {
                attempt.reject(IdentityOperation::CaptureAtr, IdentityError::StatusFailed);
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
            Err(_) => {
                attempt.reject(
                    IdentityOperation::CaptureAtr,
                    IdentityError::BoundaryPanicked,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
        };
        attempt.observed_atr = Some(atr.clone());
        let observed_protocol = protocol.map(|protocol| match protocol {
            Protocol::T0 => NegotiatedProtocol::T0,
            Protocol::T1 => NegotiatedProtocol::T1,
            Protocol::RAW => NegotiatedProtocol::Raw,
        });
        attempt.observed_protocol = observed_protocol;
        if atr.is_empty() {
            attempt.reject(IdentityOperation::CaptureAtr, IdentityError::AtrEmpty);
            finish_disconnect(&mut attempt, card);
            return attempt;
        }
        if atr.len() > MAX_ATR_BYTES {
            attempt.reject(IdentityOperation::CaptureAtr, IdentityError::AtrTooLong);
            finish_disconnect(&mut attempt, card);
            return attempt;
        }
        if atr != REGISTERED_J3R180_ATR {
            attempt.reject(
                IdentityOperation::CaptureAtr,
                IdentityError::RegisteredAtrMismatch,
            );
            finish_disconnect(&mut attempt, card);
            return attempt;
        }
        attempt.push_pass(IdentityOperation::CaptureAtr);

        let Some(protocol) = observed_protocol else {
            attempt.reject(
                IdentityOperation::CaptureProtocol,
                IdentityError::ProtocolUnavailable,
            );
            finish_disconnect(&mut attempt, card);
            return attempt;
        };
        if protocol != NegotiatedProtocol::T1 {
            attempt.reject(
                IdentityOperation::CaptureProtocol,
                IdentityError::IdentityProtocolMismatch,
            );
            finish_disconnect(&mut attempt, card);
            return attempt;
        }
        attempt.push_pass(IdentityOperation::CaptureProtocol);

        attempt.exchanges[0].request = Some(CARD_RECOGNITION_COMMAND.to_vec());
        let mut card_recognition_buffer = [0u8; MAX_IDENTITY_RESPONSE_BYTES];
        let card_recognition = match catch_unwind(AssertUnwindSafe(|| {
            card.transmit(&CARD_RECOGNITION_COMMAND, &mut card_recognition_buffer)
                .map(<[u8]>::to_vec)
        })) {
            Ok(Ok(response)) => {
                attempt.push_pass(IdentityOperation::TransmitCardRecognition);
                response
            }
            Ok(Err(pcsc::Error::InsufficientBuffer)) => {
                attempt.reject(
                    IdentityOperation::TransmitCardRecognition,
                    IdentityError::CardRecognitionResponseTooLong,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
            Ok(Err(_)) => {
                attempt.reject(
                    IdentityOperation::TransmitCardRecognition,
                    IdentityError::CardRecognitionTransmitFailed,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
            Err(_) => {
                attempt.reject(
                    IdentityOperation::TransmitCardRecognition,
                    IdentityError::BoundaryPanicked,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
        };
        attempt.exchanges[0].response = Some(card_recognition.clone());
        match validate_card_recognition_response(&card_recognition) {
            Ok(()) => attempt.push_pass(IdentityOperation::ReceiveCardRecognition),
            Err(error) => {
                attempt.reject(IdentityOperation::ReceiveCardRecognition, error);
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
        }

        attempt.exchanges[1].request = Some(CPLC_COMMAND.to_vec());
        let mut cplc_buffer = [0u8; MAX_IDENTITY_RESPONSE_BYTES];
        let cplc = match catch_unwind(AssertUnwindSafe(|| {
            card.transmit(&CPLC_COMMAND, &mut cplc_buffer)
                .map(<[u8]>::to_vec)
        })) {
            Ok(Ok(response)) => {
                attempt.push_pass(IdentityOperation::TransmitCplc);
                response
            }
            Ok(Err(pcsc::Error::InsufficientBuffer)) => {
                attempt.reject(
                    IdentityOperation::TransmitCplc,
                    IdentityError::CplcResponseLengthMismatch,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
            Ok(Err(_)) => {
                attempt.reject(
                    IdentityOperation::TransmitCplc,
                    IdentityError::CplcTransmitFailed,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
            Err(_) => {
                attempt.reject(
                    IdentityOperation::TransmitCplc,
                    IdentityError::BoundaryPanicked,
                );
                finish_disconnect(&mut attempt, card);
                return attempt;
            }
        };
        attempt.exchanges[1].response = Some(cplc.clone());
        match validate_cplc_response(&cplc) {
            Ok(()) => attempt.push_pass(IdentityOperation::ReceiveCplc),
            Err(error) => attempt.reject(IdentityOperation::ReceiveCplc, error),
        }
        finish_disconnect(&mut attempt, card);
        attempt
    }
}

fn finish_disconnect(attempt: &mut IdentityAttempt, card: pcsc::Card) {
    match catch_unwind(AssertUnwindSafe(|| card.disconnect(Disposition::LeaveCard))) {
        Ok(Ok(())) => attempt.finish_disconnect(true),
        Ok(Err((card, _))) => {
            mem::forget(card);
            attempt.finish_disconnect(false);
        }
        Err(_) => {
            attempt.disconnected = Some(false);
            attempt.reject(
                IdentityOperation::Disconnect,
                IdentityError::BoundaryPanicked,
            );
        }
    }
}
