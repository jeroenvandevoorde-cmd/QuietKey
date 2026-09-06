use qk_card_enrollment::{
    fixed_sitting_plan, SittingMode, MAX_SITTING_REQUEST_BYTES, MAX_SITTING_RESPONSE_BYTES,
};
use qk_card_model::{CardModel, ModelLifecycle, RESPONSE_BYTES};
use qk_card_protocol::Media;

const GOLDEN: &str =
    include_str!("../../../host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

fn replay(mode: SittingMode) -> CardModel {
    let plan = fixed_sitting_plan(mode).expect("registered sitting plan");
    let mut model = CardModel::new();
    for exchange in plan.exchanges() {
        assert!(exchange.request().len() <= MAX_SITTING_REQUEST_BYTES);
        assert!(exchange.expected_response().len() <= MAX_SITTING_RESPONSE_BYTES);
        assert_ne!(exchange.request().get(1), Some(&0x15), "SIGN is absent");
        let mut response = [0u8; RESPONSE_BYTES];
        let length = model
            .process_apdu(Media::ContactT1, exchange.request(), &mut response)
            .unwrap_or_else(|error| {
                panic!(
                    "model rejected {} exchange {}: {error}",
                    mode.as_str(),
                    exchange.index()
                )
            });
        assert_eq!(
            &response[..length],
            exchange.expected_response(),
            "{} exchange {}",
            mode.as_str(),
            exchange.index()
        );
    }
    model
}

#[test]
fn install_information_plan_is_byte_exact_in_a_fresh_model() {
    let model = replay(SittingMode::InstallInfo);
    assert_eq!(model.lifecycle(), ModelLifecycle::Unprovisioned);
}

#[test]
fn provisioning_and_setup_readback_plan_is_byte_exact_in_a_fresh_model() {
    let model = replay(SittingMode::ProvisionGolden);
    assert_eq!(model.lifecycle(), ModelLifecycle::Committed);
}

#[test]
fn provision_plan_derivation_changes_only_the_three_rowed_normal_fields() {
    let plan = fixed_sitting_plan(SittingMode::ProvisionGolden).expect("registered plan");
    let exchanges = plan.exchanges();
    let setup_names = [
        "setup_select",
        "setup_open",
        "setup_begin",
        "setup_write_0",
        "setup_write_192",
        "setup_write_384",
        "setup_write_576",
        "setup_write_768",
        "setup_commit",
    ];
    for (index, name) in setup_names.iter().enumerate() {
        assert_eq!(
            exchanges[index].request(),
            golden_hex(&format!("{name}_request_hex"))
        );
        assert_eq!(
            exchanges[index].expected_response(),
            golden_hex(&format!("{name}_response_hex"))
        );
    }

    assert_eq!(
        exchanges[9].request(),
        golden_hex("normal_select_request_hex")
    );
    assert_eq!(
        exchanges[9].expected_response(),
        golden_hex("normal_select_response_hex")
    );

    let mut open = golden_hex("normal_open_request_hex");
    assert_eq!(open[6], 2);
    open[6] = 1;
    assert_eq!(exchanges[10].request(), open);
    assert_eq!(
        exchanges[10].expected_response(),
        golden_hex("normal_open_response_hex")
    );

    assert_eq!(
        exchanges[11].request(),
        golden_hex("normal_info_request_hex")
    );
    let mut info = golden_hex("normal_info_response_hex");
    let mask = info.len() - 4;
    assert_eq!(&info[mask..mask + 2], &[0x00, 0x0f]);
    info[mask + 1] = 0x07;
    assert_eq!(exchanges[11].expected_response(), info);

    for (index, name) in [
        "normal_read_1_0",
        "normal_read_1_192",
        "normal_read_2_0",
        "normal_read_2_192",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            exchanges[index + 12].request(),
            golden_hex(&format!("{name}_request_hex"))
        );
        assert_eq!(
            exchanges[index + 12].expected_response(),
            golden_hex(&format!("{name}_response_hex"))
        );
    }

    let mut a2_request = golden_hex("normal_a2_request_hex");
    let purpose = a2_request.len() - 2;
    assert_eq!(a2_request[purpose], 2);
    a2_request[purpose] = 1;
    assert_eq!(exchanges[16].request(), a2_request);
    let mut a2_response = golden_hex("normal_a2_response_hex");
    assert_eq!(a2_response[21], 2);
    a2_response[21] = 1;
    assert_eq!(exchanges[16].expected_response(), a2_response);
}

fn golden_hex(name: &str) -> Vec<u8> {
    let prefix = format!("{name}: ");
    let value = GOLDEN
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing GOLDEN fact {name}"));
    decode_hex(value)
}

fn decode_hex(value: &str) -> Vec<u8> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "odd-length GOLDEN hex");
    pairs
        .iter()
        .map(|pair| (digit(pair[0]) << 4) | digit(pair[1]))
        .collect()
}

fn digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("non-canonical GOLDEN hex"),
    }
}
