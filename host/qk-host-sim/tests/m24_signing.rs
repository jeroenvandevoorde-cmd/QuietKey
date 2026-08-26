//! M24 HOST signing/finalization against the exact public NEVER-FUND fixture.

use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_sim::{
    FinalizedTransaction, M24SigningError, MockCardRole, MockCardSignature, ReviewReadyWorkflow,
    TerminalInputKey,
};
use qk_psbt::{canonical_serialize, parse, InputSource, SemanticCategory, SemanticError};
use qk_secp::{secret_key_import, SecpError};
use std::collections::BTreeMap;

#[path = "../../qk-psbt/src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &str = include_str!("fixtures/m24_signing.txt");
const FIXTURE_BYTES: usize = 30_808;
const FIXTURE_LF: usize = 235;
const FIXTURE_SHA256: &str = "06c37a4d6de189d6e4eb6eaba7f3ac5f695671a0e55419c15a7f9068b262d7c9";

type Case = BTreeMap<String, String>;

fn cases() -> Vec<Case> {
    FIXTURE
        .split("\n\n")
        .filter(|block| block.lines().any(|line| line.starts_with("case: ")))
        .map(|block| {
            let mut fields = Case::new();
            for line in block.lines() {
                let (name, value) = line.split_once(": ").expect("fixture field separator");
                assert!(fields.insert(name.to_owned(), value.to_owned()).is_none());
            }
            fields
        })
        .collect()
}

fn global_field(name: &str) -> &str {
    FIXTURE
        .lines()
        .take_while(|line| !line.starts_with("case: "))
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("global fixture field")
}

fn field<'a>(case: &'a Case, name: &str) -> &'a str {
    case.get(name).map(String::as_str).expect("case field")
}

fn case_named<'a>(all: &'a [Case], name: &str) -> &'a Case {
    all.iter()
        .find(|case| field(case, "case") == name)
        .expect("named fixture case")
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

fn sha256(value: &[u8]) -> [u8; 32] {
    let mut hasher = fixture_sha256::Sha256::new();
    hasher.update(value).expect("fixture hash update");
    hasher.finalize().expect("fixture hash finalization")
}

fn sha256d(value: &[u8]) -> [u8; 32] {
    sha256(&sha256(value))
}

fn descriptor() -> DescriptorPair {
    parse_descriptor_pair(
        global_field("receive_descriptor").as_bytes(),
        global_field("change_descriptor").as_bytes(),
    )
    .expect("fixture descriptor pair")
}

fn reach_review_ready(s0: &[u8]) -> ReviewReadyWorkflow {
    let mut workflow = ReviewReadyWorkflow::new(descriptor()).expect("workflow construction");
    workflow
        .intake(s0, InputSource::MicroSd)
        .expect("bounded immutable intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validation");
    workflow.construct_review().expect("review construction");
    let ready = workflow.review_ready().expect("ReviewReady result");
    assert_eq!(ready.s0_len(), s0.len());
    assert_eq!(ready.s0_sha256(), sha256(s0));
    assert_eq!(ready.input_source(), InputSource::MicroSd);
    workflow
}

fn imported_terminal(input_index: u32, scalar_field: &str) -> TerminalInputKey {
    let mut source = decode_hex_32(global_field(scalar_field));
    let secret = secret_key_import(&mut source).expect("public fixture scalar import");
    assert_eq!(source, [0u8; 32], "secret source must be wiped");
    TerminalInputKey::new(input_index, secret)
}

fn role(value: &str) -> MockCardRole {
    match value {
        "B" => MockCardRole::B,
        "C" => MockCardRole::C,
        _ => panic!("closed mock role"),
    }
}

fn run_case(case: &Case) -> FinalizedTransaction {
    let s0 = decode_hex(global_field("initial_psbt_hex"));
    let der = decode_hex(global_field(&format!(
        "signature_{}_der_hex",
        field(case, "mock_signature_0_role").to_ascii_lowercase()
    )));
    let mock = [MockCardSignature {
        input_index: field(case, "mock_signature_0_input_index")
            .parse()
            .expect("mock input index"),
        role: role(field(case, "mock_signature_0_role")),
        der_signature: &der,
    }];
    reach_review_ready(&s0)
        .sign_and_finalize_m24(
            vec![imported_terminal(
                field(case, "terminal_input_0_index")
                    .parse()
                    .expect("terminal input index"),
                "role_a_route_private_scalar_hex",
            )],
            &mock,
        )
        .expect("M24 fixture completes")
}

fn assert_global_artifact(prefix: &str) {
    let bytes = decode_hex(global_field(&format!("{prefix}_hex")));
    assert_eq!(
        bytes.len(),
        global_field(&format!("{prefix}_len"))
            .parse::<usize>()
            .expect("artifact length")
    );
    assert_eq!(
        sha256(&bytes),
        decode_hex_32(global_field(&format!("{prefix}_sha256")))
    );
}

fn assert_case_artifact(case: &Case, prefix: &str) {
    let bytes = decode_hex(field(case, &format!("{prefix}_hex")));
    assert_eq!(
        bytes.len(),
        field(case, &format!("{prefix}_len"))
            .parse::<usize>()
            .expect("artifact length")
    );
    assert_eq!(
        sha256(&bytes),
        decode_hex_32(field(case, &format!("{prefix}_sha256")))
    );
}

fn assert_psbt_fixed_point(bytes: &[u8], partials: usize, final_witnesses: usize) {
    let view = parse(bytes, InputSource::MicroSd).expect("fixture PSBT parse");
    assert_eq!(
        canonical_serialize(&view).expect("canonical fixture serialization"),
        bytes
    );
    let records = view.input_records(0).expect("one input map");
    let mut partial_count = 0usize;
    let mut final_witness_count = 0usize;
    for record in records {
        if record.key_type == 0x02 {
            partial_count += 1;
        }
        if record.key_type == 0x08 {
            final_witness_count += 1;
        }
    }
    assert_eq!(partial_count, partials);
    assert_eq!(final_witness_count, final_witnesses);
}

fn assert_exact_final(case: &Case, finalized: &FinalizedTransaction) {
    let expected_psbt = decode_hex(field(case, "finalized_psbt_hex"));
    let expected_raw = decode_hex(field(case, "raw_tx_hex"));
    assert_eq!(finalized.finalized_psbt(), expected_psbt);
    assert_eq!(finalized.raw_transaction(), expected_raw);
    assert_eq!(finalized.txid(), decode_hex_32(field(case, "txid_raw_hex")));
    assert_eq!(
        finalized.wtxid(),
        decode_hex_32(field(case, "wtxid_raw_hex"))
    );
    let mut txid_display = finalized.txid();
    txid_display.reverse();
    let mut wtxid_display = finalized.wtxid();
    wtxid_display.reverse();
    assert_eq!(txid_display, decode_hex_32(field(case, "txid_display_hex")));
    assert_eq!(
        wtxid_display,
        decode_hex_32(field(case, "wtxid_display_hex"))
    );
}

fn expect_error(result: Result<FinalizedTransaction, M24SigningError>, expected: M24SigningError) {
    match result {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("expected named M24 rejection"),
    }
}

fn expect_existing_signature_error(
    result: Result<FinalizedTransaction, M24SigningError>,
    category: SemanticCategory,
) {
    match result {
        Err(M24SigningError::ExistingSignatureVerification(SemanticError {
            category: actual,
            ..
        })) => assert_eq!(actual, category),
        Err(other) => panic!("wrong M24 rejection: {other:?}"),
        Ok(_) => panic!("expected existing-signature rejection"),
    }
}

fn replace_once_same_len(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let matches: Vec<usize> = bytes
        .windows(from.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == from).then_some(index))
        .collect();
    assert_eq!(matches.len(), 1, "replacement source must occur once");
    let start = matches[0];
    bytes[start..start + to.len()].copy_from_slice(to);
}

fn stage_with_role_a_only() -> Vec<u8> {
    let all = cases();
    let ab = case_named(&all, "M24-A-B");
    let mut stage = decode_hex(field(ab, "stage_1_psbt_hex"));
    let b_key = decode_hex(global_field("signature_b_public_key_hex"));
    let a_key = decode_hex(global_field("signature_a_public_key_hex"));
    let mut old_record_key = vec![0x22, 0x02];
    old_record_key.extend_from_slice(&b_key);
    let mut new_record_key = vec![0x22, 0x02];
    new_record_key.extend_from_slice(&a_key);
    replace_once_same_len(&mut stage, &old_record_key, &new_record_key);
    replace_once_same_len(
        &mut stage,
        &decode_hex(global_field("signature_b_complete_hex")),
        &decode_hex(global_field("signature_a_complete_hex")),
    );
    assert_psbt_fixed_point(&stage, 1, 0);
    stage
}

#[test]
fn fixture_identity_inventory_and_all_literal_artifacts_are_closed() {
    let bytes = FIXTURE.as_bytes();
    assert_eq!(bytes.len(), FIXTURE_BYTES);
    assert_eq!(
        bytes.iter().filter(|byte| **byte == b'\n').count(),
        FIXTURE_LF
    );
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\r').count(), 0);
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert!(bytes.is_ascii());
    assert_eq!(sha256(bytes), decode_hex_32(FIXTURE_SHA256));
    assert!(FIXTURE.starts_with("# PERMANENTLY NEVER-FUND\n"));
    assert_eq!(global_field("funding_status"), "PERMANENTLY NEVER-FUND");
    for role in ['a', 'b', 'c'] {
        assert_eq!(
            global_field(&format!("role_{role}_seed_ascii")),
            format!(
                "QuietKey/M24/NEVER-FUND/fixture-only/role-{}/v1",
                role.to_ascii_uppercase()
            )
        );
    }
    assert_eq!(global_field("route_branch"), "0");
    assert_eq!(global_field("route_index"), "7");
    assert_eq!(global_field("receive_descriptor_len"), "445");
    assert_eq!(global_field("change_descriptor_len"), "445");
    assert_eq!(global_field("wallet_transcript_len"), "891");
    assert_eq!(
        sha256(&decode_hex(global_field("wallet_transcript_hex"))),
        decode_hex_32(global_field("wallet_id_hex"))
    );

    for prefix in [
        "wallet_transcript",
        "witness_script",
        "p2wsh_script_pubkey",
        "previous_tx",
        "witness_utxo",
        "unsigned_tx",
        "initial_psbt",
        "bip143_preimage",
        "signature_a_der",
        "signature_a_complete",
        "signature_b_der",
        "signature_b_complete",
        "signature_c_der",
        "signature_c_complete",
    ] {
        assert_global_artifact(prefix);
    }
    assert_eq!(
        sha256d(&decode_hex(global_field("bip143_preimage_hex"))),
        decode_hex_32(global_field("bip143_digest_hex"))
    );
    for role in ['a', 'b', 'c'] {
        let der = decode_hex(global_field(&format!("signature_{role}_der_hex")));
        let complete = decode_hex(global_field(&format!("signature_{role}_complete_hex")));
        assert_eq!(complete.split_last(), Some((&1u8, der.as_slice())));
    }

    let all = cases();
    assert_eq!(all.len(), 2);
    assert_eq!(
        field(case_named(&all, "M24-A-B"), "insertion_order_roles"),
        "B,A"
    );
    assert_eq!(
        field(case_named(&all, "M24-A-C"), "insertion_order_roles"),
        "C,A"
    );
    for case in &all {
        assert_eq!(field(case, "class"), "complete");
        assert_eq!(field(case, "expected"), "complete");
        for prefix in [
            "stage_1_psbt",
            "completed_psbt",
            "final_witness",
            "finalized_psbt",
            "raw_tx",
            "stripped_tx",
        ] {
            assert_case_artifact(case, prefix);
        }
        let stripped = decode_hex(field(case, "stripped_tx_hex"));
        let raw = decode_hex(field(case, "raw_tx_hex"));
        assert_eq!(
            sha256d(&stripped),
            decode_hex_32(field(case, "txid_raw_hex"))
        );
        assert_eq!(sha256d(&raw), decode_hex_32(field(case, "wtxid_raw_hex")));
    }
}

#[test]
fn initial_stage_complete_and_finalized_psbts_are_canonical() {
    assert_psbt_fixed_point(&decode_hex(global_field("initial_psbt_hex")), 0, 0);
    for case in cases() {
        assert_psbt_fixed_point(&decode_hex(field(&case, "stage_1_psbt_hex")), 1, 0);
        assert_psbt_fixed_point(&decode_hex(field(&case, "completed_psbt_hex")), 2, 0);
        assert_psbt_fixed_point(&decode_hex(field(&case, "finalized_psbt_hex")), 0, 1);
    }
}

#[test]
fn review_ready_to_ab_and_ac_matches_every_final_oracle() {
    let all = cases();
    for name in ["M24-A-B", "M24-A-C"] {
        let case = case_named(&all, name);
        let finalized = run_case(case);
        // The terminal DER is not exposed by the API. Exact finalized-PSBT and
        // raw-transaction equality therefore ties it indirectly to the fixture.
        assert_exact_final(case, &finalized);
    }
}

#[test]
fn scalar_import_wipes_the_caller_source() {
    for role in ['a', 'b', 'c'] {
        let mut source = decode_hex_32(global_field(&format!(
            "role_{role}_route_private_scalar_hex"
        )));
        let _secret = secret_key_import(&mut source).expect("public fixture scalar");
        assert_eq!(source, [0u8; 32]);
    }
}

#[test]
fn invalid_mock_and_wrong_role_reject_without_an_artifact() {
    let s0 = decode_hex(global_field("initial_psbt_hex"));
    let b = decode_hex(global_field("signature_b_der_hex"));
    let c = decode_hex(global_field("signature_c_der_hex"));
    for (claimed, der) in [
        (MockCardRole::B, c.as_slice()),
        (MockCardRole::C, b.as_slice()),
    ] {
        let mock = [MockCardSignature {
            input_index: 0,
            role: claimed,
            der_signature: der,
        }];
        expect_error(
            reach_review_ready(&s0).sign_and_finalize_m24(
                vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
                &mock,
            ),
            M24SigningError::InvalidMockSignature,
        );
    }
}

#[test]
fn wrong_terminal_key_rejects_at_the_self_verification_boundary() {
    let s0 = decode_hex(global_field("initial_psbt_hex"));
    let b = decode_hex(global_field("signature_b_der_hex"));
    let mock = [MockCardSignature {
        input_index: 0,
        role: MockCardRole::B,
        der_signature: &b,
    }];
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_b_route_private_scalar_hex")],
            &mock,
        ),
        M24SigningError::TerminalSigning(SecpError::SelfVerificationFailed),
    );
}

#[test]
fn missing_duplicate_unexpected_and_out_of_range_terminal_inputs_are_named() {
    let s0 = decode_hex(global_field("initial_psbt_hex"));
    let b = decode_hex(global_field("signature_b_der_hex"));
    let mock_b = [MockCardSignature {
        input_index: 0,
        role: MockCardRole::B,
        der_signature: &b,
    }];
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(Vec::new(), &mock_b),
        M24SigningError::MissingTerminalKey,
    );
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![
                imported_terminal(0, "role_a_route_private_scalar_hex"),
                imported_terminal(0, "role_a_route_private_scalar_hex"),
            ],
            &mock_b,
        ),
        M24SigningError::DuplicateTerminalKey,
    );
    expect_error(
        reach_review_ready(&stage_with_role_a_only()).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &mock_b,
        ),
        M24SigningError::UnexpectedTerminalKey,
    );
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(1, "role_a_route_private_scalar_hex")],
            &mock_b,
        ),
        M24SigningError::InputOutOfRange,
    );
    let mock_out_of_range = [MockCardSignature {
        input_index: 1,
        role: MockCardRole::B,
        der_signature: &b,
    }];
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &mock_out_of_range,
        ),
        M24SigningError::InputOutOfRange,
    );
}

#[test]
fn threshold_and_role_failures_are_distinct() {
    let all = cases();
    let ab = case_named(&all, "M24-A-B");
    let s0 = decode_hex(global_field("initial_psbt_hex"));
    let complete = decode_hex(field(ab, "completed_psbt_hex"));
    let b = decode_hex(global_field("signature_b_der_hex"));
    let c = decode_hex(global_field("signature_c_der_hex"));
    let mock_b = MockCardSignature {
        input_index: 0,
        role: MockCardRole::B,
        der_signature: &b,
    };
    let mock_c = MockCardSignature {
        input_index: 0,
        role: MockCardRole::C,
        der_signature: &c,
    };

    expect_error(
        reach_review_ready(&complete).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &[],
        ),
        M24SigningError::ThresholdAlreadyMet,
    );
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &[mock_b, mock_c],
        ),
        M24SigningError::ThresholdWouldBeExceeded,
    );
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &[],
        ),
        M24SigningError::ThresholdIncomplete,
    );
    let wrong_second_b = MockCardSignature {
        input_index: 0,
        role: MockCardRole::B,
        der_signature: &c,
    };
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &[mock_b, wrong_second_b],
        ),
        M24SigningError::DuplicateRole,
    );

    let stage_b = decode_hex(field(ab, "stage_1_psbt_hex"));
    expect_error(
        reach_review_ready(&stage_b).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &[wrong_second_b],
        ),
        M24SigningError::SignatureConflict,
    );
}

#[test]
fn exact_duplicate_precedence_is_same_for_same_role_cross_role_and_existing_replay() {
    let all = cases();
    let ab = case_named(&all, "M24-A-B");
    let s0 = decode_hex(global_field("initial_psbt_hex"));
    let stage_b = decode_hex(field(ab, "stage_1_psbt_hex"));
    let b = decode_hex(global_field("signature_b_der_hex"));
    let same_role = [
        MockCardSignature {
            input_index: 0,
            role: MockCardRole::B,
            der_signature: &b,
        },
        MockCardSignature {
            input_index: 0,
            role: MockCardRole::B,
            der_signature: &b,
        },
    ];
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &same_role,
        ),
        M24SigningError::DuplicateSignature,
    );

    let cross_role = [
        MockCardSignature {
            input_index: 0,
            role: MockCardRole::B,
            der_signature: &b,
        },
        MockCardSignature {
            input_index: 0,
            role: MockCardRole::C,
            der_signature: &b,
        },
    ];
    expect_error(
        reach_review_ready(&s0).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &cross_role,
        ),
        M24SigningError::DuplicateSignature,
    );

    let replay = [MockCardSignature {
        input_index: 0,
        role: MockCardRole::B,
        der_signature: &b,
    }];
    expect_error(
        reach_review_ready(&stage_b).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &replay,
        ),
        M24SigningError::DuplicateSignature,
    );
}

#[test]
fn invalid_existing_signature_is_rejected_before_new_signatures() {
    let all = cases();
    let ab = case_named(&all, "M24-A-B");
    let mut stage = decode_hex(field(ab, "stage_1_psbt_hex"));
    let valid = decode_hex(global_field("signature_b_complete_hex"));
    let mut invalid = valid.clone();
    let last_der_byte = invalid.len() - 2;
    invalid[last_der_byte] ^= 1;
    replace_once_same_len(&mut stage, &valid, &invalid);
    assert_psbt_fixed_point(&stage, 1, 0);
    expect_existing_signature_error(
        reach_review_ready(&stage).sign_and_finalize_m24(
            vec![imported_terminal(0, "role_a_route_private_scalar_hex")],
            &[],
        ),
        SemanticCategory::SignatureVerificationFailed,
    );
}
