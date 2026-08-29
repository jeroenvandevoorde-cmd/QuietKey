//! Public v2 provisioning behavior over the registered GOLDEN fixture.

use qk_descriptor::{derive_change_script_v2, derive_receive_script_v2, parse_descriptor_pair_v2};
use qk_provisioning::{HostProvisioningRunV2, ProvisioningArtifactsV2, ProvisioningError};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("fixtures/provisioning_v2.txt");

fn fields() -> BTreeMap<&'static str, &'static str> {
    let mut fields = BTreeMap::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").expect("framed public fact");
        assert!(fields.insert(name, value).is_none(), "unique field {name}");
    }
    assert_eq!(fields.len(), 66);
    fields
}

fn field<'a>(facts: &'a BTreeMap<&str, &str>, name: &str) -> &'a str {
    facts.get(name).copied().expect("fixture field")
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
        *slot = u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex");
    }
    output
}

fn transcripts() -> [[u8; 100]; 4] {
    let facts = fields();
    [
        field(&facts, "seed_a_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("Seed-A transcript"),
        field(&facts, "signer_b_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("Signer-B transcript"),
        field(&facts, "kit_r_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("Kit-R transcript"),
        field(&facts, "a2_transcript_ascii")
            .as_bytes()
            .try_into()
            .expect("A2 transcript"),
    ]
}

fn construct(values: &[[u8; 100]; 4]) -> Result<HostProvisioningRunV2, ProvisioningError> {
    HostProvisioningRunV2::from_manual_dice([&values[0], &values[1], &values[2], &values[3]])
}

fn complete() -> ProvisioningArtifactsV2 {
    let values = transcripts();
    let facts = fields();
    let nonce = hex_array::<12>(facts["a1_nonce_hex"]);
    construct(&values)
        .expect("valid v2 GOLDEN transcripts")
        .encrypt_a1(&nonce)
        .expect("one capsule")
}

#[test]
fn exact_public_v2_facts_reparse_and_capsule_authenticates() {
    let facts = fields();
    let artifacts = complete();
    assert_eq!(artifacts.account_xpubs.len(), 2);
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
    assert_eq!(artifacts.wallet_id, hex_array(facts["wallet_id"]));
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
        .expect("strict v2 descriptor reparse");
    assert_eq!(pair.wallet_id(), artifacts.wallet_id);
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
    qk_a1::decrypt(
        &a2,
        &artifacts.wallet_id,
        &artifacts.a1_capsule,
        &mut opened,
    )
    .expect("A1 authentication");
    assert_eq!(opened, hex_array(facts["a1_plaintext_hex"]));
    opened.fill(0);
}

#[test]
fn manual_profile_count_symbol_and_reuse_precedence_is_named() {
    let values = transcripts();
    assert_eq!(
        HostProvisioningRunV2::from_manual_dice([
            &values[0][..99],
            &values[1],
            &values[2],
            &values[3],
        ])
        .err()
        .expect("99 symbols reject"),
        ProvisioningError::DiceCount
    );

    let mut long = values[0].to_vec();
    long.push(b'1');
    assert_eq!(
        HostProvisioningRunV2::from_manual_dice([&long, &values[1], &values[2], &values[3],])
            .err()
            .expect("101 symbols reject"),
        ProvisioningError::DiceCount
    );
    long[100] = b'0';
    assert_eq!(
        HostProvisioningRunV2::from_manual_dice([&long, &values[1], &values[2], &values[3],])
            .err()
            .expect("overflow count precedes an unstoreable symbol"),
        ProvisioningError::DiceCount
    );

    let mut invalid = values;
    invalid[0][99] = b'0';
    invalid[1] = invalid[0];
    assert_eq!(
        construct(&invalid)
            .err()
            .expect("malformed transcript precedes reuse"),
        ProvisioningError::InvalidDiceSymbol
    );

    let grid_sized = [b'1'; 125];
    assert_eq!(
        HostProvisioningRunV2::from_manual_dice([&grid_sized, &values[1], &values[2], &values[3],])
            .err()
            .expect("DiceGrid is not a slice-4 entry"),
        ProvisioningError::DiceCount
    );

    const PAIRS: [(usize, usize); 6] = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
    for (left, right) in PAIRS {
        let mut reused = values;
        reused[right] = reused[left];
        assert_eq!(
            construct(&reused).err().expect("every reuse pair rejects"),
            ProvisioningError::TranscriptReuse,
            "reuse pair {left},{right}"
        );
    }
}

#[test]
fn v2_a1_nonce_state_is_single_output_and_cross_run_is_host_only() {
    let values = transcripts();
    let facts = fields();
    let nonce = hex_array::<12>(facts["a1_nonce_hex"]);
    let mut other = nonce;
    other[11] ^= 1;

    let mut first_run = construct(&values).expect("first run");
    let first = first_run.encrypt_a1(&nonce).expect("first capsule");
    assert_eq!(
        first_run.encrypt_a1(&nonce),
        Err(ProvisioningError::NonceReuse)
    );
    assert_eq!(
        first_run.encrypt_a1(&other),
        Err(ProvisioningError::AlreadyEncrypted)
    );

    let fresh = construct(&values)
        .expect("fresh HOST run")
        .encrypt_a1(&nonce)
        .expect("cross-run freshness is a target obligation");
    assert_eq!(fresh, first);
}
