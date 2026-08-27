use crate::bip39::vector_entropy_to_mnemonic_and_seed;
use crate::qkec::condition_four;
use crate::sha256::sha256;
use crate::HostProvisioningRun;
use qk_descriptor::{derive_change_script, derive_receive_script, parse_descriptor_pair};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("../tests/fixtures/m26_provisioning_e2e.txt");

fn fields() -> BTreeMap<&'static str, &'static str> {
    let mut fields = BTreeMap::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        let (name, value) = line.split_once(": ").expect("framed public fact");
        assert!(fields.insert(name, value).is_none(), "unique field {name}");
    }
    assert_eq!(fields.len(), 72, "exact public fact count");
    fields
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

fn record(facts: &BTreeMap<&str, &str>, role: &str) -> Vec<u8> {
    let mut output = vec![1u8];
    for tag in 1..=3 {
        let ascii_name = format!("source_{role}_{tag:02}_ascii");
        let record_name = format!("record_{role}_{tag:02}_hex");
        let ascii = facts[ascii_name.as_str()];
        assert_eq!(ascii.len(), 32);
        assert_eq!(ascii, format!("QuietKey/M26/NEVER-FUND/{role}/{tag:02}!!!"));
        let fragment = hex_vec(facts[record_name.as_str()]);
        assert_eq!(fragment.len(), 35);
        assert_eq!(fragment[0], tag);
        assert_eq!(&fragment[1..3], &32u16.to_be_bytes());
        assert_eq!(&fragment[3..], ascii.as_bytes());
        output.extend_from_slice(&fragment);
    }
    assert_eq!(output.len(), 106);
    output
}

fn field<'a>(facts: &'a BTreeMap<&str, &str>, name: &str) -> &'a str {
    facts.get(name).copied().expect("fixture field")
}

#[test]
fn complete_two_constructor_fixture_recomputes_through_real_host_path() {
    assert_eq!(FIXTURE.len(), 10_509);
    assert_eq!(FIXTURE.bytes().filter(|&byte| byte == b'\n').count(), 96);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    assert_eq!(
        hex_text(&sha256(FIXTURE.as_bytes())),
        "62544345997f3cc0e6d8a4d2249b3c276942d09390802370739b32efec661a99"
    );
    let facts = fields();
    assert_eq!(facts["format"], "QUIETKEY_M26_E2E_PUBLIC_FACTS_V1");
    assert_eq!(facts["funding_status"], "PERMANENTLY_NEVER_FUND");
    assert_eq!(facts["record_version_hex"], "01");

    let records = [
        record(&facts, "SA"),
        record(&facts, "SB"),
        record(&facts, "SC"),
        record(&facts, "A2"),
    ];
    let ceremony_id = hex_array::<16>(facts["ceremony_id_hex"]);
    assert_eq!(&ceremony_id, b"M26-CEREMONY-001");
    let conditioned = condition_four(
        [&records[0], &records[1], &records[2], &records[3]],
        &ceremony_id,
    )
    .expect("canonical public QKEC records");

    for (index, role) in ["SA", "SB", "SC", "A2"].iter().enumerate() {
        assert_eq!(
            hex_text(&sha256(conditioned[index].as_bytes())),
            field(&facts, &format!("qkec_{role}_output_sha256"))
        );
    }
    for (index, role) in ["A", "B", "C"].iter().enumerate() {
        let (mut mnemonic, mut seed) =
            vector_entropy_to_mnemonic_and_seed(conditioned[index].as_bytes(), b"")
                .expect("fixed English empty-passphrase profile");
        assert_eq!(
            hex_text(&sha256(&mnemonic)),
            field(&facts, &format!("role_{role}_mnemonic_sha256"))
        );
        assert_eq!(
            hex_text(&sha256(&seed)),
            field(&facts, &format!("role_{role}_bip39_seed_sha256"))
        );
        mnemonic.fill(0);
        seed.fill(0);
    }

    let nonce = hex_array::<12>(facts["public_nonce_hex"]);
    assert_eq!(&nonce, b"M26-NONCE-01");
    let mut run = HostProvisioningRun::from_qkec(
        [&records[0], &records[1], &records[2], &records[3]],
        &ceremony_id,
    )
    .expect("complete run");
    let artifacts = run.encrypt_a1(&nonce).expect("first capsule");

    for (index, role) in ["A", "B", "C"].iter().enumerate() {
        assert_eq!(
            artifacts.account_xpubs[index].as_slice(),
            field(&facts, &format!("role_{role}_account_xpub")).as_bytes()
        );
    }
    assert_eq!(
        artifacts.descriptors[0].as_slice(),
        facts["receive_descriptor"].as_bytes()
    );
    assert_eq!(
        artifacts.descriptors[1].as_slice(),
        facts["change_descriptor"].as_bytes()
    );
    assert_eq!(hex_text(&artifacts.wallet_id), facts["wallet_id"]);
    assert_eq!(
        hex_text(&artifacts.first_scripts[0]),
        facts["receive_0_script_pubkey"]
    );
    assert_eq!(
        hex_text(&artifacts.first_scripts[1]),
        facts["change_0_script_pubkey"]
    );
    assert_eq!(
        artifacts.first_addresses[0].as_slice(),
        facts["receive_0_address"].as_bytes()
    );
    assert_eq!(
        artifacts.first_addresses[1].as_slice(),
        facts["change_0_address"].as_bytes()
    );
    assert_eq!(hex_text(&artifacts.a1_capsule), facts["a1_capsule_hex"]);
    assert_eq!(
        hex_text(&sha256(&artifacts.a1_capsule)),
        facts["a1_capsule_sha256"]
    );

    let mut aad = [0u8; 39];
    aad[..7].copy_from_slice(&artifacts.a1_capsule[..7]);
    aad[7..].copy_from_slice(&artifacts.wallet_id);
    assert_eq!(hex_text(&sha256(&aad)), facts["a1_aad_sha256"]);
    aad.fill(0);

    let pair = parse_descriptor_pair(&artifacts.descriptors[0], &artifacts.descriptors[1])
        .expect("generated descriptors reparse");
    assert_eq!(pair.wallet_id(), artifacts.wallet_id);
    for (branch, derived) in [
        derive_receive_script(&pair, 0).expect("receive zero"),
        derive_change_script(&pair, 0).expect("change zero"),
    ]
    .iter()
    .enumerate()
    {
        let prefix = if branch == 0 { "receive_0" } else { "change_0" };
        assert_eq!(
            hex_text(&derived.witness_script),
            field(&facts, &format!("{prefix}_witness_script"))
        );
        assert_eq!(
            hex_text(&derived.script_pubkey),
            field(&facts, &format!("{prefix}_script_pubkey"))
        );
        let mut role_keys = [
            hex_array::<33>(field(&facts, &format!("{prefix}_role_A_pubkey"))),
            hex_array::<33>(field(&facts, &format!("{prefix}_role_B_pubkey"))),
            hex_array::<33>(field(&facts, &format!("{prefix}_role_C_pubkey"))),
        ];
        role_keys.sort();
        for (index, actual) in role_keys.iter().enumerate() {
            let expected =
                hex_array::<33>(field(&facts, &format!("{prefix}_sorted_{index}_pubkey")));
            assert_eq!(*actual, expected);
            let offset = 2 + index * 34;
            assert_eq!(&derived.witness_script[offset..offset + 33], &expected);
        }
    }

    let mut decrypted = [0u8; 32];
    qk_a1::decrypt(
        conditioned[3].as_bytes(),
        &artifacts.wallet_id,
        &artifacts.a1_capsule,
        &mut decrypted,
    )
    .expect("fixture capsule authenticates");
    assert_eq!(&decrypted, conditioned[0].as_bytes());
    decrypted.fill(0);
}
