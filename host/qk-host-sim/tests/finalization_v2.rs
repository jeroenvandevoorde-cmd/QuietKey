//! Exact 2-of-2 witness/final-PSBT/raw-transaction binding for slice 3.

use qk_descriptor::parse_descriptor_pair_v2;
use qk_host_sim::{MockCardBSignature, ReviewReadyV3Workflow, TerminalInputKeyV2};
use qk_psbt::{canonical_serialize, parse, InputSource};
use qk_secp::secret_key_import;

const FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

fn field(name: &str) -> &'static str {
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("v2 finalization fixture field")
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

fn finalized_from(s0: &[u8]) -> qk_host_sim::FinalizedTransaction {
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
    let descriptor = parse_descriptor_pair_v2(receive.as_bytes(), change.as_bytes())
        .expect("v2 fixture descriptor");
    let mut workflow = ReviewReadyV3Workflow::new(descriptor).expect("workflow");
    workflow
        .intake(s0, InputSource::MicroSd)
        .expect("immutable intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validate");
    workflow.construct_review().expect("review v3");

    let mut scalar = decode_hex_32(field("role_a_route_private_scalar_hex"));
    let terminal = TerminalInputKeyV2::new(
        0,
        secret_key_import(&mut scalar).expect("public fixture scalar"),
    );
    assert_eq!(scalar, [0u8; 32]);
    let b = decode_hex(field("role_b_der_hex"));
    workflow
        .sign_and_finalize_v2(
            vec![terminal],
            &[MockCardBSignature {
                input_index: 0,
                der_signature: &b,
            }],
        )
        .expect("v2 signing/finalization")
}

fn finalized() -> qk_host_sim::FinalizedTransaction {
    finalized_from(&decode_hex(field("s0_hex")))
}

#[test]
fn final_psbt_has_the_only_ratified_delta_and_at_least_121_byte_shrink() {
    let result = finalized();
    let complete = decode_hex(field("threshold_complete_psbt_hex"));
    let expected = decode_hex(field("finalized_psbt_hex"));
    assert_eq!(result.finalized_psbt(), expected);
    let shrink = complete
        .len()
        .checked_sub(result.finalized_psbt().len())
        .expect("finalized PSBT is smaller");
    assert!(shrink >= 121);
    assert_eq!(shrink, 128, "fixture also removes one type-03 record");

    let before = parse(&complete, InputSource::MicroSd).expect("complete PSBT");
    let after = parse(result.finalized_psbt(), InputSource::MicroSd).expect("final PSBT");
    assert_eq!(
        canonical_serialize(&after).expect("M5 final fixed point"),
        result.finalized_psbt()
    );
    assert_eq!(before.unsigned_tx_bytes(), after.unsigned_tx_bytes());
    assert_eq!(
        before.global_map_span().slice(before.buffer()),
        after.global_map_span().slice(after.buffer())
    );

    let records: Vec<_> = after.input_records(0).expect("one input").collect();
    assert_eq!(
        records
            .iter()
            .filter(|record| (0x02..=0x07).contains(&record.key_type))
            .count(),
        0
    );
    let final_record = records
        .iter()
        .find(|record| record.key_type == 0x08)
        .expect("one final witness");
    assert!(final_record.key_data.is_empty());
    assert_eq!(final_record.value, decode_hex(field("final_witness_hex")));
    assert_eq!(
        records
            .iter()
            .filter(|record| record.key_type == 0x08)
            .count(),
        1
    );
}

#[test]
fn raw_transaction_is_exactly_rebound_and_identifiers_are_raw_order() {
    let result = finalized();
    let raw = decode_hex(field("raw_transaction_hex"));
    assert_eq!(result.raw_transaction(), raw);
    assert_eq!(result.txid(), decode_hex_32(field("txid_raw_hex")));
    assert_eq!(result.wtxid(), decode_hex_32(field("wtxid_raw_hex")));

    let mut txid_display = result.txid();
    txid_display.reverse();
    let mut wtxid_display = result.wtxid();
    wtxid_display.reverse();
    assert_eq!(txid_display, decode_hex_32(field("txid_display_hex")));
    assert_eq!(wtxid_display, decode_hex_32(field("wtxid_display_hex")));

    let view = parse(result.finalized_psbt(), InputSource::MicroSd).expect("final PSBT");
    let witness = decode_hex(field("final_witness_hex"));
    assert_eq!(
        raw.len(),
        view.unsigned_tx_bytes().len() + 2 + witness.len()
    );
    assert_eq!(witness.len(), 220, "fixture reaches the exact witness cap");
    assert_eq!(witness.first(), Some(&0x04));
    assert_eq!(witness.get(1), Some(&0x00));
    assert_eq!(witness.last(), Some(&0xae));
}

#[test]
fn proprietary_input_record_is_preserved_while_signing_fields_are_replaced() {
    let mut s0 = decode_hex(field("s0_hex"));
    let view = parse(&s0, InputSource::MicroSd).expect("base S0");
    let insert_at = view
        .input_map_span(0)
        .expect("one input map")
        .end
        .checked_sub(1)
        .expect("map separator");
    let proprietary = [0x01, 0xfc, 0x01, 0xaa];
    s0.splice(insert_at..insert_at, proprietary);

    let result = finalized_from(&s0);
    assert_eq!(
        result.raw_transaction(),
        decode_hex(field("raw_transaction_hex"))
    );
    let finalized_view =
        parse(result.finalized_psbt(), InputSource::MicroSd).expect("finalized PSBT");
    let records: Vec<_> = finalized_view
        .input_records(0)
        .expect("one input")
        .collect();
    let retained = records
        .iter()
        .find(|record| record.key_type == 0xfc)
        .expect("proprietary record retained");
    assert!(retained.key_data.is_empty());
    assert_eq!(retained.value, [0xaa]);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.key_type == 0x08)
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| (0x02..=0x07).contains(&record.key_type))
            .count(),
        0
    );
}

#[test]
fn finalizer_surface_exposes_no_arbitrary_capability_constructor() {
    let source = include_str!("../src/finalization_v2.rs");
    assert!(!source.contains("pub fn finalize_v2"));
    assert!(!source.contains("pub struct ThresholdComplete"));
    assert!(!source.contains("DescriptorRole"));
    assert!(!source.contains("RoleC"));
    assert!(!source.contains("approval"));
    assert!(!source.contains("card_session"));
    assert!(!source.contains("export"));
}
