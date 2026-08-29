//! V2 A+B HOST signing continuation over the registered public GOLDEN vector.

use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_host_sim::{
    FinalizedTransaction, MockCardBSignature, ReviewReadyV3Workflow, SigningV2Error,
    TerminalInputKeyV2,
};
use qk_psbt::{InputSource, SemanticCategory, SemanticError};
use qk_secp::secret_key_import;

const FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

fn field(name: &str) -> &'static str {
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("v2 signing fixture field")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    decode_hex(value).try_into().expect("exact 32-byte field")
}

fn descriptor() -> DescriptorPairV2 {
    let golden = DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .expect("GOLDEN descriptor block");
    let receive = golden
        .lines()
        .find_map(|line| line.strip_prefix("receive: "))
        .expect("GOLDEN receive descriptor");
    let change = golden
        .lines()
        .find_map(|line| line.strip_prefix("change: "))
        .expect("GOLDEN change descriptor");
    parse_descriptor_pair_v2(receive.as_bytes(), change.as_bytes()).expect("v2 fixture descriptor")
}

fn reach_review_ready(s0: &[u8]) -> ReviewReadyV3Workflow {
    let mut workflow = ReviewReadyV3Workflow::new(descriptor()).expect("workflow");
    workflow
        .intake(s0, InputSource::MicroSd)
        .expect("immutable intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validate");
    workflow.construct_review().expect("construct review v3");
    workflow
}

fn terminal_key(field_name: &str) -> TerminalInputKeyV2 {
    let mut bytes = decode_hex_32(field(field_name));
    let key = secret_key_import(&mut bytes).expect("public fixture scalar");
    assert_eq!(bytes, [0u8; 32]);
    TerminalInputKeyV2::new(0, key)
}

fn sign(s0: &[u8]) -> Result<FinalizedTransaction, SigningV2Error> {
    let role_b = decode_hex(field("role_b_der_hex"));
    let mock = [MockCardBSignature {
        input_index: 0,
        der_signature: &role_b,
    }];
    reach_review_ready(s0)
        .sign_and_finalize_v2(vec![terminal_key("role_a_route_private_scalar_hex")], &mock)
}

fn expect_error(result: Result<FinalizedTransaction, SigningV2Error>, expected: SigningV2Error) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("expected named v2 signing rejection"),
    }
}

#[test]
fn public_a_and_mock_b_produce_the_exact_final_artifacts() {
    let s0 = decode_hex(field("s0_hex"));
    let finalized = sign(&s0).expect("v2 A+B signing and finalization");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field("finalized_psbt_hex"))
    );
    assert_eq!(
        finalized.raw_transaction(),
        decode_hex(field("raw_transaction_hex"))
    );
    assert_eq!(finalized.txid(), decode_hex_32(field("txid_raw_hex")));
    assert_eq!(finalized.wtxid(), decode_hex_32(field("wtxid_raw_hex")));
}

#[test]
fn wrong_terminal_missing_terminal_and_invalid_b_are_distinct() {
    let s0 = decode_hex(field("s0_hex"));
    let role_b = decode_hex(field("role_b_der_hex"));
    let mock = [MockCardBSignature {
        input_index: 0,
        der_signature: &role_b,
    }];
    expect_error(
        reach_review_ready(&s0)
            .sign_and_finalize_v2(vec![terminal_key("role_b_route_private_scalar_hex")], &mock),
        SigningV2Error::TerminalKeyMismatch,
    );
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_v2(Vec::new(), &mock),
        SigningV2Error::MissingTerminalKey,
    );
    let mut invalid_b = role_b;
    let last = invalid_b.last_mut().expect("nonempty DER");
    *last ^= 1;
    let invalid_mock = [MockCardBSignature {
        input_index: 0,
        der_signature: &invalid_b,
    }];
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_v2(
            vec![terminal_key("role_a_route_private_scalar_hex")],
            &invalid_mock,
        ),
        SigningV2Error::InvalidMockSignature,
    );
}

#[test]
fn duplicate_inputs_roles_and_signatures_are_named_before_mutation() {
    let s0 = decode_hex(field("s0_hex"));
    let role_b = decode_hex(field("role_b_der_hex"));
    let mock = MockCardBSignature {
        input_index: 0,
        der_signature: &role_b,
    };
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_v2(
            vec![
                terminal_key("role_a_route_private_scalar_hex"),
                terminal_key("role_a_route_private_scalar_hex"),
            ],
            &[mock],
        ),
        SigningV2Error::DuplicateTerminalKey,
    );
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_v2(
            vec![terminal_key("role_a_route_private_scalar_hex")],
            &[mock, mock],
        ),
        SigningV2Error::DuplicateSignature,
    );
    let role_a = decode_hex(field("role_a_der_hex"));
    let distinct_second = MockCardBSignature {
        input_index: 0,
        der_signature: &role_a,
    };
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_v2(
            vec![terminal_key("role_a_route_private_scalar_hex")],
            &[mock, distinct_second],
        ),
        SigningV2Error::DuplicateRole,
    );
}

#[test]
fn complete_inputs_receive_no_new_record_and_bad_existing_crypto_rejects() {
    let complete = decode_hex(field("threshold_complete_psbt_hex"));
    let finalized = reach_review_ready(&complete)
        .sign_and_finalize_v2(Vec::new(), &[])
        .expect("already-complete valid input finalizes without insertion");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field("finalized_psbt_hex"))
    );

    let role_b = decode_hex(field("role_b_der_hex"));
    let mock = [MockCardBSignature {
        input_index: 0,
        der_signature: &role_b,
    }];
    expect_error(
        reach_review_ready(&complete)
            .sign_and_finalize_v2(vec![terminal_key("role_a_route_private_scalar_hex")], &mock),
        SigningV2Error::ThresholdAlreadyMet,
    );

    let mut invalid = complete;
    let needle = decode_hex(field("role_b_der_hex"));
    let start = invalid
        .windows(needle.len())
        .position(|candidate| candidate == needle)
        .expect("role-B signature occurs once");
    invalid[start + needle.len() - 1] ^= 1;
    match reach_review_ready(&invalid).sign_and_finalize_v2(Vec::new(), &[]) {
        Err(SigningV2Error::ExistingSignatureVerification(SemanticError {
            category: SemanticCategory::SignatureVerificationFailed,
            ..
        })) => {}
        Err(other) => panic!("wrong existing-signature rejection: {other:?}"),
        Ok(_) => panic!("invalid existing signature accepted"),
    }
}

#[test]
fn valid_existing_a_is_verified_and_only_missing_b_is_inserted() {
    let stage_a = decode_hex(field("after_role_a_psbt_hex"));
    let role_b = decode_hex(field("role_b_der_hex"));
    let finalized = reach_review_ready(&stage_a)
        .sign_and_finalize_v2(
            Vec::new(),
            &[MockCardBSignature {
                input_index: 0,
                der_signature: &role_b,
            }],
        )
        .expect("existing A plus verified mock B");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field("finalized_psbt_hex"))
    );
    expect_error(
        reach_review_ready(&stage_a).sign_and_finalize_v2(
            vec![terminal_key("role_a_route_private_scalar_hex")],
            &[MockCardBSignature {
                input_index: 0,
                der_signature: &role_b,
            }],
        ),
        SigningV2Error::UnexpectedTerminalKey,
    );
}

#[test]
fn byte_equal_optional_witness_script_is_accepted_and_removed_at_finalization() {
    let mut s0 = decode_hex(field("s0_hex"));
    let first_derivation = s0
        .windows(2)
        .position(|candidate| candidate == [0x22, 0x06])
        .expect("first derivation record");
    let script = decode_hex(field("witness_script_hex"));
    let mut record = Vec::with_capacity(3 + script.len());
    record.extend_from_slice(&[0x01, 0x05, 0x47]);
    record.extend_from_slice(&script);
    s0.splice(first_derivation..first_derivation, record);

    let finalized = sign(&s0).expect("byte-equal optional witnessScript");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field("finalized_psbt_hex"))
    );
}

#[test]
fn valid_existing_b_requires_only_a_and_rejects_an_occupied_b_response() {
    let mut b_only = decode_hex(field("threshold_complete_psbt_hex"));
    let a_key = decode_hex(field("role_a_route_public_key_hex"));
    let a_der = decode_hex(field("role_a_der_hex"));
    let mut a_record = Vec::new();
    a_record.extend_from_slice(&[0x22, 0x02]);
    a_record.extend_from_slice(&a_key);
    a_record.push(u8::try_from(a_der.len() + 1).expect("bounded complete signature"));
    a_record.extend_from_slice(&a_der);
    a_record.push(0x01);
    let start = b_only
        .windows(a_record.len())
        .position(|candidate| candidate == a_record)
        .expect("exact role-A record");
    b_only.drain(start..start + a_record.len());

    let finalized = reach_review_ready(&b_only)
        .sign_and_finalize_v2(vec![terminal_key("role_a_route_private_scalar_hex")], &[])
        .expect("existing B plus terminal A");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field("finalized_psbt_hex"))
    );

    let distinct_mock = decode_hex(field("role_a_der_hex"));
    expect_error(
        reach_review_ready(&b_only).sign_and_finalize_v2(
            vec![terminal_key("role_a_route_private_scalar_hex")],
            &[MockCardBSignature {
                input_index: 0,
                der_signature: &distinct_mock,
            }],
        ),
        SigningV2Error::SignatureConflict,
    );
}

#[test]
fn public_terminal_wrapper_has_no_secret_observation_surface() {
    let source = include_str!("../src/signing_v2.rs");
    let terminal = source
        .split_once("pub struct TerminalInputKeyV2 {")
        .expect("terminal type")
        .1
        .split_once("}\n")
        .expect("terminal body")
        .0;
    assert!(!terminal.contains("pub "));
    for forbidden in [
        "impl Debug for TerminalInputKeyV2",
        "impl Clone for TerminalInputKeyV2",
        "impl Copy for TerminalInputKeyV2",
        "MockCardRole",
        "RoleC",
        "CycleToken",
        "RequestApproval",
        "card_session",
        "export_transport",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
}
