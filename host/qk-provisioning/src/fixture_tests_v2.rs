use crate::hkdf_sha256::{expand, extract};
use crate::secret::wipe;
use crate::sha256::sha256;
use crate::HostProvisioningRunV2;
use qk_descriptor::{derive_change_script_v2, derive_receive_script_v2, parse_descriptor_pair_v2};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("../tests/fixtures/provisioning_v2.txt");

fn fields() -> BTreeMap<&'static str, &'static str> {
    let mut fields = BTreeMap::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").expect("framed public fact");
        assert!(fields.insert(name, value).is_none(), "unique field {name}");
    }
    assert_eq!(fields.len(), 66, "exact public fact count");
    fields
}

fn field<'a>(facts: &'a BTreeMap<&str, &str>, name: &str) -> &'a str {
    facts.get(name).copied().expect("fixture field")
}

fn hex_vec(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|position| u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex"))
        .collect()
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex_vec(text)
        .try_into()
        .unwrap_or_else(|_| panic!("exact {N}-byte field"))
}

fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn transcripts(facts: &BTreeMap<&str, &str>) -> [[u8; 100]; 4] {
    [
        field(facts, "seed_a_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("100-byte Seed-A transcript"),
        field(facts, "signer_b_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("100-byte Signer-B transcript"),
        field(facts, "kit_r_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("100-byte Kit-R transcript"),
        field(facts, "a2_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("100-byte A2 transcript"),
    ]
}

#[test]
fn complete_v2_fixture_recomputes_public_artifacts_and_private_owners() {
    assert_eq!(FIXTURE.len(), 9_219);
    assert_eq!(FIXTURE.bytes().filter(|&byte| byte == b'\n').count(), 83);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    assert_eq!(
        hex_text(&sha256(FIXTURE.as_bytes())),
        "04161895860df1b672e91e3249471dde9564cef13dd72d5b3a45b240e9d79741"
    );

    let facts = fields();
    assert_eq!(
        facts["format"],
        "QUIETKEY_V2_SLICE4_PROVISIONING_PUBLIC_FACTS_V1"
    );
    assert_eq!(
        facts["funding_status"],
        "PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL"
    );
    assert_eq!(facts["profile"], "ManualKeypad");
    assert_eq!(facts["purpose_order"], "Seed-A,Signer-B,Kit-R,A2");

    let transcripts = transcripts(&facts);
    for (index, name) in [
        "seed_a_transcript_sha256",
        "signer_b_transcript_sha256",
        "kit_r_transcript_sha256",
        "a2_transcript_sha256",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(hex_text(&sha256(&transcripts[index])), facts[*name]);
    }

    let refs = [
        &transcripts[0][..],
        &transcripts[1][..],
        &transcripts[2][..],
        &transcripts[3][..],
    ];
    let mut run = HostProvisioningRunV2::from_manual_dice(refs)
        .expect("registered ManualKeypad fixture must construct");

    let expected_payload = hex_array::<96>(facts["owned_payload_hex"]);
    let expected_pad = hex_array::<96>(facts["kit_r_pad_hex"]);
    assert_eq!(run.payload.as_bytes(), &expected_payload);
    assert_eq!(run.kit_r_pad.as_bytes(), &expected_pad);
    assert_eq!(
        sha256(run.payload.as_bytes()),
        hex_array(facts["owned_payload_sha256"])
    );
    assert_eq!(
        sha256(run.kit_r_pad.as_bytes()),
        hex_array(facts["kit_r_pad_sha256"])
    );

    let t = sha256(&transcripts[2]);
    assert_eq!(t, hex_array(facts["kit_r_t_hex"]));
    let wallet_id = hex_array::<32>(facts["wallet_id"]);
    let mut salt_input = Vec::with_capacity(36);
    salt_input.extend_from_slice(b"QuietKey/QKEC-1");
    salt_input.extend_from_slice(b"Kit-R");
    salt_input.extend_from_slice(&wallet_id[..16]);
    assert_eq!(hex_text(&salt_input), facts["kit_r_salt_input_hex"]);
    let mut salt = sha256(&salt_input);
    assert_eq!(salt, hex_array(facts["kit_r_salt_hex"]));
    let mut prk = extract(&salt, &t);
    assert_eq!(prk, hex_array(facts["kit_r_prk_hex"]));
    let mut info = Vec::with_capacity(57);
    info.extend_from_slice(b"QuietKey/Kit-R/pad/v1");
    info.push(0);
    info.extend_from_slice(&wallet_id);
    assert_eq!(hex_text(&info), facts["kit_r_info_hex"]);
    let mut recomputed_pad = [0u8; 96];
    assert!(expand(&prk, &info, &mut recomputed_pad));
    assert_eq!(recomputed_pad, expected_pad);

    let nonce = hex_array::<12>(facts["a1_nonce_hex"]);
    let artifacts = run.encrypt_a1(&nonce).expect("one v2 A1 capsule");
    assert_eq!(run.payload.as_bytes(), &expected_payload);
    assert_eq!(run.kit_r_pad.as_bytes(), &expected_pad);
    assert_eq!(
        artifacts.account_xpubs[0].as_slice(),
        facts["role_a_account_xpub"].as_bytes()
    );
    assert_eq!(
        artifacts.account_xpubs[1].as_slice(),
        facts["role_b_account_xpub"].as_bytes()
    );
    assert_eq!(
        artifacts.descriptors[0].as_slice(),
        facts["receive_descriptor"].as_bytes()
    );
    assert_eq!(
        artifacts.descriptors[1].as_slice(),
        facts["change_descriptor"].as_bytes()
    );
    assert_eq!(artifacts.wallet_id, wallet_id);
    assert_eq!(
        artifacts.first_scripts[0],
        hex_array(facts["receive_0_script_pubkey"])
    );
    assert_eq!(
        artifacts.first_scripts[1],
        hex_array(facts["change_0_script_pubkey"])
    );
    assert_eq!(
        artifacts.first_addresses[0].as_slice(),
        facts["receive_0_address"].as_bytes()
    );
    assert_eq!(
        artifacts.first_addresses[1].as_slice(),
        facts["change_0_address"].as_bytes()
    );
    assert_eq!(artifacts.a1_capsule, hex_array(facts["a1_capsule_hex"]));

    let pair = parse_descriptor_pair_v2(&artifacts.descriptors[0], &artifacts.descriptors[1])
        .expect("generated v2 descriptors reparse");
    assert_eq!(pair.wallet_id(), wallet_id);
    let receive = derive_receive_script_v2(&pair, 0).expect("receive zero");
    let change = derive_change_script_v2(&pair, 0).expect("change zero");
    assert_eq!(
        receive.witness_script,
        hex_array(facts["receive_0_witness_script"])
    );
    assert_eq!(
        change.witness_script,
        hex_array(facts["change_0_witness_script"])
    );
    assert_eq!(receive.script_pubkey, artifacts.first_scripts[0]);
    assert_eq!(change.script_pubkey, artifacts.first_scripts[1]);

    let a2 = hex_array::<32>(facts["a2_transcript_sha256"]);
    let mut opened = [0xa5; 32];
    qk_a1::decrypt(&a2, &wallet_id, &artifacts.a1_capsule, &mut opened)
        .expect("fixture capsule authenticates");
    assert_eq!(opened, hex_array(facts["a1_plaintext_hex"]));

    wipe(&mut opened);
    wipe(&mut recomputed_pad);
    wipe(&mut prk);
    wipe(&mut salt);
    salt_input.fill(0);
    info.fill(0);
}
