#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_card_model::{reset_wipe_counter, wipe_counter, CardModel, ModelError, ModelLifecycle};
use qk_card_protocol::{
    parse_response, parse_structural_command, Instruction, Media, ProtocolError, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
};

const FIXTURE: &str =
    include_str!("../../host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StepFact {
    name: &'static str,
    response_len: usize,
    status: u16,
    lifecycle: ModelLifecycle,
}

fn protocol_error_name(error: ProtocolError) -> &'static str {
    let name = match error {
        ProtocolError::WrongLength => "WrongLength",
        ProtocolError::IncorrectP1P2 => "IncorrectP1P2",
        ProtocolError::InstructionNotSupported => "InstructionNotSupported",
        ProtocolError::ClassNotSupported => "ClassNotSupported",
        ProtocolError::ProtocolVersionMismatch => "ProtocolVersionMismatch",
        ProtocolError::ContactInterfaceRequired => "ContactInterfaceRequired",
        ProtocolError::SessionStateRejected => "SessionStateRejected",
        ProtocolError::SessionIdMismatch => "SessionIdMismatch",
        ProtocolError::SequenceRejected => "SequenceRejected",
        ProtocolError::ModeOrOperationRejected => "ModeOrOperationRejected",
        ProtocolError::LifecycleRejected => "LifecycleRejected",
        ProtocolError::ProvisioningOrderRejected => "ProvisioningOrderRejected",
        ProtocolError::RecordRejected => "RecordRejected",
        ProtocolError::WalletBindingRejected => "WalletBindingRejected",
        ProtocolError::DerivationPathRejected => "DerivationPathRejected",
        ProtocolError::ChildDerivationRejected => "ChildDerivationRejected",
        ProtocolError::SigningBindingRejected => "SigningBindingRejected",
        ProtocolError::CryptographicOperationRejected => "CryptographicOperationRejected",
        ProtocolError::InternalIntegrityFailure => "InternalIntegrityFailure",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn model_error_name(error: ModelError) -> &'static str {
    let name = match error {
        ModelError::ContactInterfaceRequired => "ContactInterfaceRequired",
        ModelError::ProtocolVersionMismatch => "ProtocolVersionMismatch",
        ModelError::SessionStateRejected => "SessionStateRejected",
        ModelError::SessionIdMismatch => "SessionIdMismatch",
        ModelError::SequenceRejected => "SequenceRejected",
        ModelError::ModeOrOperationRejected => "ModeOrOperationRejected",
        ModelError::LifecycleRejected => "LifecycleRejected",
        ModelError::ProvisioningOrderRejected => "ProvisioningOrderRejected",
        ModelError::RecordRejected => "RecordRejected",
        ModelError::WalletBindingRejected => "WalletBindingRejected",
        ModelError::DerivationPathRejected => "DerivationPathRejected",
        ModelError::ChildDerivationRejected => "ChildDerivationRejected",
        ModelError::SigningBindingRejected => "SigningBindingRejected",
        ModelError::CryptographicOperationRejected => "CryptographicOperationRejected",
        ModelError::InternalIntegrityFailure => "InternalIntegrityFailure",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    assert_eq!(
        error.status_word(),
        u16::from_be_bytes(error.status_word().to_be_bytes())
    );
    name
}

fn decode_fixture_flow(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let text = core::str::from_utf8(data).ok()?;
    if !data.ends_with(b"\n") {
        return None;
    }
    let registered = FIXTURE.lines().filter(|line| {
        line.split_once(": ")
            .is_some_and(|(name, _)| name.ends_with("_request_hex"))
    });
    if !text.lines().eq(registered) {
        return None;
    }
    let mut requests = Vec::new();
    for line in text.lines() {
        let (name, hex) = line.split_once(": ")?;
        if !name.ends_with("_request_hex") || hex.is_empty() || !hex.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            bytes.push(u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?);
        }
        requests.push(bytes);
    }
    (!requests.is_empty()).then_some(requests)
}

fn process_one(model: &mut CardModel, media: Media, bytes: &[u8]) -> StepFact {
    let parsed = parse_structural_command(media, bytes);
    let expected = parsed.as_ref().ok().map(|command| command.instruction());
    let mut output = [0u8; MAX_RESPONSE_BYTES];
    let result = model.process_apdu(media, bytes, &mut output);
    match result {
        Ok(length) => {
            assert!(length <= MAX_RESPONSE_BYTES);
            let instruction = expected.expect("a successful model step was parsed");
            parse_response(instruction, &output[..length])
                .expect("successful model response is canonical");
            StepFact {
                name: "Accepted",
                response_len: length,
                status: u16::from_be_bytes([output[length - 2], output[length - 1]]),
                lifecycle: model.lifecycle(),
            }
        }
        Err(error) => {
            let name = protocol_error_name(error);
            assert_eq!(output[..2], error.status_word().bytes());
            assert!(output[2..].iter().all(|byte| *byte == 0));
            if let Some(instruction) = expected {
                parse_response(instruction, &output[..2])
                    .expect("semantic model rejection belongs to the command's closed set");
            } else {
                assert_eq!(parsed.expect_err("parser rejected the same bytes"), error);
            }
            StepFact {
                name,
                response_len: 2,
                status: error.status_word().value(),
                lifecycle: model.lifecycle(),
            }
        }
    }
}

fn run_fixture(requests: &[Vec<u8>]) -> Vec<StepFact> {
    let mut model = CardModel::new();
    requests
        .iter()
        .map(|request| process_one(&mut model, Media::ContactT1, request))
        .collect()
}

fn run_structured(data: &[u8]) -> Vec<StepFact> {
    let mut model = CardModel::new();
    let mut facts = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() && facts.len() < 128 {
        let control = data[offset];
        offset += 1;
        let requested = if let Some(length) = data.get(offset..offset.saturating_add(2)) {
            offset += 2;
            usize::from(u16::from_be_bytes([length[0], length[1]])).min(MAX_REQUEST_BYTES + 1)
        } else {
            data.len().saturating_sub(offset)
        };
        let end = offset.saturating_add(requested).min(data.len());
        let media = if control & 1 == 0 {
            Media::ContactT1
        } else {
            Media::Contactless
        };
        let candidate = &data[offset..end];
        // Only the byte-exact registered fixture flow may commit signing key
        // material. Structured mutations still exercise every parser and all
        // pre-commit state, while a skipped COMMIT leaves later SIGN requests
        // unable to reach a private-key operation.
        if parse_structural_command(media, candidate)
            .is_ok_and(|command| command.instruction() == Instruction::Commit)
        {
            offset = end;
            continue;
        }
        facts.push(process_one(&mut model, media, candidate));
        offset = end;
    }
    facts
}

fn run(data: &[u8]) -> Vec<StepFact> {
    if let Some(requests) = decode_fixture_flow(data) {
        run_fixture(&requests)
    } else {
        run_structured(data)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut rejected = CardModel::new();
    let error = rejected
        .select(false)
        .expect_err("contactless selection always rejects");
    assert_eq!(model_error_name(error), "ContactInterfaceRequired");

    reset_wipe_counter();
    let first = run(data);
    let first_wiped = wipe_counter();
    reset_wipe_counter();
    let second = run(data);
    let second_wiped = wipe_counter();
    assert_eq!(first, second);
    assert_eq!(first_wiped, second_wiped);
});
