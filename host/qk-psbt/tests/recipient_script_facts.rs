//! M13's closed recipient-script-facts matrix.  The only descriptor material
//! used here is the public M11 NUMS fixture.

use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_psbt::{
    analyze_recipient_script_facts, canonical_serialize, parse, InputSource, OutputOwnership,
    RecipientType, SemanticCategory,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const FIXTURE: &str = include_str!("fixtures/recipient_script_facts.txt");
const M11: &str = include_str!("fixtures/descriptor_ownership.txt");
const FP: [[u8; 4]; 3] = [
    [0x11, 0x22, 0x33, 0x44],
    [0x55, 0x66, 0x77, 0x88],
    [0x99, 0xaa, 0xbb, 0xcc],
];
const KEYS: [&str; 3] = [
    "034e22740e550d90ccc0a008c4f01b2b3c20abff713214cdd7243cff56515e5af1",
    "022dadaac032a994507b3311d28eba41ef24976a4162b326c90c348175d7073dc3",
    "0322919fd8f093161ff0e6a33007c96ddfa63e03394b38e433a4edebfe410ec925",
];
const CHANGE_KEYS: [&str; 3] = [
    "02e15f61067285b745818d9725e7790183c53125d3725baa36ebad0b8fc595708b",
    "038a05ed2e442de87a7251e4f4ec39f4ee33c076e43d84f75519de839c830a530b",
    "0375094880a1fd05c4a83c965ab724c5c3a1fcdb9af5675e39e60b7515c5e86459",
];
const WITNESS: &str = "5221022dadaac032a994507b3311d28eba41ef24976a4162b326c90c348175d7073dc3210322919fd8f093161ff0e6a33007c96ddfa63e03394b38e433a4edebfe410ec92521034e22740e550d90ccc0a008c4f01b2b3c20abff713214cdd7243cff56515e5af153ae";
const OWNED: &str = "0020094bba024177bbe0d8df875c26e2f8c4d46afb1f7cdd8fa6566c85b271d5955e";
const CHANGE: &str = "002085015c1a505f29cd6038af4d389808e0bab86e97adb6e9989ced032a972713ba";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn descriptor() -> DescriptorPair {
    let get = |p| M11.lines().find_map(|l| l.strip_prefix(p)).unwrap();
    parse_descriptor_pair(get("receive: ").as_bytes(), get("change: ").as_bytes()).unwrap()
}
fn cs(b: &mut Vec<u8>, n: usize) {
    if n < 253 {
        b.push(n as u8)
    } else {
        b.push(253);
        b.extend_from_slice(&(n as u16).to_le_bytes())
    }
}
fn rec(b: &mut Vec<u8>, ty: u8, kd: &[u8], value: &[u8]) {
    cs(b, kd.len() + 1);
    b.push(ty);
    b.extend_from_slice(kd);
    cs(b, value.len());
    b.extend_from_slice(value);
}
fn sha256(b: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut p = b.to_vec();
    let bit = (p.len() as u64) * 8;
    p.push(0x80);
    while p.len() % 64 != 56 {
        p.push(0)
    }
    p.extend_from_slice(&bit.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for x in p.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(x[i * 4..i * 4 + 4].try_into().unwrap())
        }
        for i in 16..64 {
            let a = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let c = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(a)
                .wrapping_add(w[i - 7])
                .wrapping_add(c)
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut z) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let t = z
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let u = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            z = g;
            g = f;
            f = e;
            e = d.wrapping_add(t);
            d = c;
            c = b;
            b = a;
            a = t.wrapping_add(u)
        }
        h = [
            h[0].wrapping_add(a),
            h[1].wrapping_add(b),
            h[2].wrapping_add(c),
            h[3].wrapping_add(d),
            h[4].wrapping_add(e),
            h[5].wrapping_add(f),
            h[6].wrapping_add(g),
            h[7].wrapping_add(z),
        ];
    }
    let mut o = [0; 32];
    for (i, v) in h.iter().enumerate() {
        o[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes())
    }
    o
}
fn dsha(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}
fn claims(b: &mut Vec<u8>, ty: u8, branch: u32) {
    let keys = if branch == 0 { &KEYS } else { &CHANGE_KEYS };
    for (i, k) in keys.iter().enumerate() {
        let mut v = FP[i].to_vec();
        for n in [0x80000030, 0x80000000, 0x80000000, 0x80000002, branch, 0] {
            v.extend_from_slice(&n.to_le_bytes())
        }
        rec(b, ty, &hex(k), &v)
    }
}
/// Fully populated v0: non_witness_utxo, matching witness_utxo, witnessScript,
/// and the exact public M12 A/B/C claims. `owned` adds output claims.
fn psbt(outputs: &[(u64, Vec<u8>)], owned: Option<(usize, u32)>, bad_sig: bool) -> Vec<u8> {
    let prev_script = hex(OWNED);
    let mut prev = vec![];
    prev.extend_from_slice(&1u32.to_le_bytes());
    prev.push(1);
    prev.extend_from_slice(&[7; 32]);
    prev.extend_from_slice(&0u32.to_le_bytes());
    prev.push(0);
    prev.extend_from_slice(&u32::MAX.to_le_bytes());
    prev.push(1);
    prev.extend_from_slice(&1_000_000u64.to_le_bytes());
    cs(&mut prev, prev_script.len());
    prev.extend_from_slice(&prev_script);
    prev.extend_from_slice(&0u32.to_le_bytes());
    let mut u = 2u32.to_le_bytes().to_vec();
    u.push(1);
    u.extend_from_slice(&dsha(&prev));
    u.extend_from_slice(&0u32.to_le_bytes());
    u.push(0);
    u.extend_from_slice(&u32::MAX.to_le_bytes());
    cs(&mut u, outputs.len());
    for (s, v) in outputs {
        u.extend_from_slice(&s.to_le_bytes());
        cs(&mut u, v.len());
        u.extend_from_slice(v)
    }
    u.extend_from_slice(&0u32.to_le_bytes());
    let mut p = b"psbt\xff".to_vec();
    rec(&mut p, 0, &[], &u);
    p.push(0);
    rec(&mut p, 0, &[], &prev);
    let mut wu = 1_000_000u64.to_le_bytes().to_vec();
    cs(&mut wu, prev_script.len());
    wu.extend_from_slice(&prev_script);
    rec(&mut p, 1, &[], &wu);
    rec(&mut p, 5, &[], &hex(WITNESS));
    claims(&mut p, 6, 0);
    if bad_sig {
        rec(&mut p, 2, &hex(KEYS[0]), &[0x30, 6, 2, 1, 1, 2, 1, 1, 1])
    }
    p.push(0);
    for (i, _) in outputs.iter().enumerate() {
        if let Some((index, branch)) = owned {
            if index == i {
                claims(&mut p, 2, branch)
            }
        }
        p.push(0)
    }
    p
}
fn fixture(name: &str, class: &str, expected: &str) {
    let b = FIXTURE
        .split("\n\n")
        .find(|b| b.lines().any(|l| l == format!("case: {name}")))
        .unwrap();
    assert!(b.contains(&format!("class: {class}")));
    assert!(b.contains(&format!("expected: {expected}")))
}
fn ok(bytes: &[u8]) -> qk_psbt::RecipientScriptAnalysis<'_> {
    let before = bytes.to_vec();
    let v = parse(bytes, InputSource::MicroSd).unwrap();
    let c = canonical_serialize(&v).unwrap();
    let a = analyze_recipient_script_facts(&v, &descriptor()).unwrap();
    assert_eq!(bytes, before);
    assert_eq!(c, canonical_serialize(&v).unwrap());
    a
}
fn reject(bytes: &[u8], want: SemanticCategory) {
    let before = bytes.to_vec();
    let v = parse(bytes, InputSource::MicroSd).unwrap();
    let c = canonical_serialize(&v).unwrap();
    let e = analyze_recipient_script_facts(&v, &descriptor()).unwrap_err();
    assert_eq!(e.category, want);
    assert_eq!(bytes, before);
    assert_eq!(c, canonical_serialize(&v).unwrap());
}
fn op(n: usize) -> Vec<u8> {
    let mut s = vec![0x6a];
    if n <= 75 {
        s.push(n as u8)
    } else {
        s.extend_from_slice(&[0x4c, n as u8])
    };
    s.extend(std::iter::repeat_n(0x66, n));
    s
}

#[test]
fn recipient_script_facts_closed_matrix() {
    assert_eq!(FIXTURE.len(), 3_043);
    assert!(FIXTURE.ends_with('\n'));
    assert_eq!(
        sha256(FIXTURE.as_bytes()),
        hex("e47af371aeb2eea7ad065fe487be6930121d139559eb9f4f41f15d8a5e3f8b1d").as_slice()
    );
    assert_eq!(
        FIXTURE.lines().filter(|x| x.starts_with("case: ")).count(),
        31
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|x| *x == "class: returned-fact")
            .count(),
        17
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|x| *x == "class: named-rejection")
            .count(),
        14
    );
    assert_eq!(qk_psbt::limits::MAX_OP_RETURN_PAYLOAD_BYTES, 80);
    for (category, display) in [
        (
            SemanticCategory::BarePubkeyRecipientScript,
            "bare pubkey recipient script rejected",
        ),
        (
            SemanticCategory::BareMultisigRecipientScript,
            "bare multisig recipient script rejected",
        ),
        (
            SemanticCategory::FutureWitnessVersion,
            "future witness version rejected",
        ),
        (
            SemanticCategory::MalformedWitnessProgram,
            "witness program malformed",
        ),
        (
            SemanticCategory::UnsupportedRecipientScript,
            "recipient script unsupported",
        ),
        (
            SemanticCategory::OpReturnNonZeroValue,
            "OP_RETURN value must be zero",
        ),
        (
            SemanticCategory::MultipleOpReturnOutputs,
            "multiple OP_RETURN outputs",
        ),
        (
            SemanticCategory::OpReturnMultiplePushes,
            "OP_RETURN has multiple pushes",
        ),
        (
            SemanticCategory::OpReturnNonMinimalPush,
            "OP_RETURN push encoding nonminimal",
        ),
        (
            SemanticCategory::OpReturnPayloadTooLong,
            "OP_RETURN payload exceeds byte cap",
        ),
    ] {
        assert_eq!(category.to_string(), display);
    }
    let templates = [
        (
            "R01",
            "p2wpkh-program20",
            "p2wpkh",
            RecipientType::P2wpkh,
            2,
        ),
        ("R02", "p2wsh-program32", "p2wsh", RecipientType::P2wsh, 2),
        (
            "R03",
            "destination-only-p2tr-program32",
            "p2tr",
            RecipientType::P2tr,
            2,
        ),
        ("R04", "p2pkh-hash20", "p2pkh", RecipientType::P2pkh, 3),
        ("R05", "p2sh-hash20", "p2sh", RecipientType::P2sh, 2),
        (
            "R06",
            "op-return-no-push-empty-data",
            "op_return_no_push",
            RecipientType::OpReturn,
            1,
        ),
    ];
    for (case, label, field, kind, start) in templates {
        fixture(case, "returned-fact", label);
        let script = hex(FIXTURE
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{field}: ")))
            .unwrap());
        let b = psbt(
            &[(
                if kind == RecipientType::OpReturn {
                    0
                } else {
                    9000
                },
                script.clone(),
            )],
            None,
            false,
        );
        let a = ok(&b);
        let f = a.recipient_outputs[0].unwrap();
        assert_eq!(f.recipient_type, kind);
        let len = match kind {
            RecipientType::P2wsh | RecipientType::P2tr => 32,
            RecipientType::OpReturn => 0,
            _ => 20,
        };
        assert_eq!(f.data, &script[start..start + len]);
        assert_eq!(&b[f.data_span.start..f.data_span.end], f.data)
    }
    for (case, n, label) in [
        ("R07", 0, "op-return-op-zero-empty-data"),
        ("R08", 1, "op-return-direct-push-1"),
        ("R09", 75, "op-return-direct-push-75"),
        ("R10", 76, "op-return-pushdata1-76"),
        ("R11", 80, "op-return-pushdata1-80"),
    ] {
        fixture(case, "returned-fact", label);
        let s = if n == 0 { vec![0x6a, 0] } else { op(n) };
        let bytes = psbt(&[(0, s)], None, false);
        let a = ok(&bytes);
        let facts = a.recipient_outputs[0].unwrap();
        assert_eq!(facts.recipient_type, RecipientType::OpReturn);
        assert_eq!(facts.data, vec![0x66; n]);
        assert_eq!(
            &bytes[facts.data_span.start..facts.data_span.end],
            facts.data
        );
    }
    fixture("R12", "returned-fact", "one-op-return-zero-value");
    ok(&psbt(
        &[
            (0, op(1)),
            (9000, hex("00141111111111111111111111111111111111111111")),
        ],
        None,
        false,
    ));
    fixture("R13", "returned-fact", "ordinary-zero-value-no-warning");
    ok(&psbt(
        &[(0, hex("00141111111111111111111111111111111111111111"))],
        None,
        false,
    ));
    fixture("R14", "returned-fact", "mixed-six-recipient-types");
    let s = [
        hex("00141111111111111111111111111111111111111111"),
        hex("00202222222222222222222222222222222222222222222222222222222222222222"),
        hex("51203333333333333333333333333333333333333333333333333333333333333333"),
        hex("76a914444444444444444444444444444444444444444488ac"),
        hex("a914555555555555555555555555555555555555555587"),
        op(1),
    ];
    let outs = s
        .iter()
        .enumerate()
        .map(|(i, x)| (if i == 5 { 0 } else { 9000 }, x.clone()))
        .collect::<Vec<_>>();
    let mixed_bytes = psbt(&outs, None, false);
    let analysis = ok(&mixed_bytes);
    let types = analysis
        .recipient_outputs
        .iter()
        .map(|facts| facts.unwrap().recipient_type)
        .collect::<Vec<_>>();
    assert_eq!(
        types,
        [
            RecipientType::P2wpkh,
            RecipientType::P2wsh,
            RecipientType::P2tr,
            RecipientType::P2pkh,
            RecipientType::P2sh,
            RecipientType::OpReturn,
        ]
    );
    fixture("R15", "returned-fact", "proven-change-preserved");
    let bytes = psbt(&[(9000, hex(CHANGE))], Some((0, 1)), false);
    let a = ok(&bytes);
    assert_eq!(
        a.ownership.wallet.outputs[0],
        OutputOwnership::ProvenChange(0)
    );
    assert_eq!(a.recipient_outputs, [None]);
    fixture("R16", "returned-fact", "proven-self-transfer-preserved");
    let bytes = psbt(&[(9000, hex(OWNED))], Some((0, 0)), false);
    let a = ok(&bytes);
    assert_eq!(
        a.ownership.wallet.outputs[0],
        OutputOwnership::ProvenSelfTransfer(0)
    );
    assert_eq!(a.recipient_outputs, [None]);
    fixture("R17", "returned-fact", "max-32-output-classification");
    let o = (0..32)
        .map(|_| (9000, hex("00141111111111111111111111111111111111111111")))
        .collect::<Vec<_>>();
    assert!(ok(&psbt(&o, None, false))
        .recipient_outputs
        .iter()
        .all(|facts| facts.is_some_and(|fact| fact.recipient_type == RecipientType::P2wpkh)));
    for (case, script, cat) in [
        (
            "E01",
            vec![0x21, 2]
                .into_iter()
                .chain(std::iter::repeat_n(1, 32))
                .chain([0xac])
                .collect(),
            SemanticCategory::BarePubkeyRecipientScript,
        ),
        (
            "E02",
            vec![0x51, 0x21, 2]
                .into_iter()
                .chain(std::iter::repeat_n(1, 32))
                .chain([0x51, 0xae])
                .collect(),
            SemanticCategory::BareMultisigRecipientScript,
        ),
        (
            "E03",
            vec![0x52, 0x20]
                .into_iter()
                .chain(std::iter::repeat_n(1, 32))
                .collect(),
            SemanticCategory::FutureWitnessVersion,
        ),
        (
            "E04",
            vec![0, 1, 1],
            SemanticCategory::MalformedWitnessProgram,
        ),
        (
            "E05",
            vec![0x61],
            SemanticCategory::UnsupportedRecipientScript,
        ),
    ] {
        fixture(case, "named-rejection", &format!("{cat:?}"));
        reject(&psbt(&[(9000, script)], None, false), cat)
    }
    for s in [
        vec![0x6a, 1, 1, 1, 2],
        vec![0x6a, 0x4c, 1, 1],
        vec![0x6a, 0x4c],
        vec![0x6a, 2, 1],
    ] {
        let cat = if s == vec![0x6a, 1, 1, 1, 2] {
            SemanticCategory::OpReturnMultiplePushes
        } else if s == vec![0x6a, 0x4c, 1, 1] {
            SemanticCategory::OpReturnNonMinimalPush
        } else {
            SemanticCategory::MalformedScriptPush
        };
        reject(&psbt(&[(0, s)], None, false), cat)
    }
    fixture("E06", "named-rejection", "OpReturnNonZeroValue");
    reject(
        &psbt(&[(1, op(1))], None, false),
        SemanticCategory::OpReturnNonZeroValue,
    );
    fixture("E07", "named-rejection", "MultipleOpReturnOutputs");
    reject(
        &psbt(&[(0, op(1)), (1, op(1))], None, false),
        SemanticCategory::MultipleOpReturnOutputs,
    );
    fixture("E08", "named-rejection", "OpReturnMultiplePushes");
    fixture("E09", "named-rejection", "OpReturnNonMinimalPush");
    fixture("E10", "named-rejection", "OpReturnPayloadTooLong");
    let nonminimal_75 = [
        vec![0x6a, 0x4c, 75],
        std::iter::repeat_n(0x66, 75).collect(),
    ]
    .concat();
    for script in [vec![0x6a, 0x4c, 0], nonminimal_75.clone()] {
        reject(
            &psbt(&[(0, script)], None, false),
            SemanticCategory::OpReturnNonMinimalPush,
        );
    }
    reject(
        &psbt(&[(0, op(81))], None, false),
        SemanticCategory::OpReturnPayloadTooLong,
    );
    for script in [vec![0x6a, 1, 1, 1, 2], nonminimal_75.clone(), op(81)] {
        reject(
            &psbt(&[(1, script)], None, false),
            SemanticCategory::OpReturnNonZeroValue,
        );
    }
    reject(
        &psbt(&[(1, vec![0x6a, 2, 1])], None, false),
        SemanticCategory::MalformedScriptPush,
    );
    for second in [nonminimal_75, op(81), vec![0x6a, 1, 1, 1, 2]] {
        reject(
            &psbt(&[(0, op(1)), (1, second)], None, false),
            SemanticCategory::MultipleOpReturnOutputs,
        );
    }
    reject(
        &psbt(&[(0, op(1)), (1, vec![0x6a, 2, 1])], None, false),
        SemanticCategory::MalformedScriptPush,
    );
    fixture("E11", "named-rejection", "MalformedScriptPush");
    fixture("E12", "named-rejection", "SignatureVerificationFailed");
    reject(
        &psbt(&[(9000, vec![0x61])], None, true),
        SemanticCategory::SignatureVerificationFailed,
    );
    fixture("E13", "named-rejection", "DescriptorOutputScriptMismatch");
    reject(
        &psbt(&[(9000, vec![0x61])], Some((0, 0)), false),
        SemanticCategory::DescriptorOutputScriptMismatch,
    );
    fixture("E14", "named-rejection", "TooManyOutputs");
    assert_eq!(
        parse(
            &psbt(
                &(0..33)
                    .map(|_| (1, hex("00141111111111111111111111111111111111111111")))
                    .collect::<Vec<_>>(),
                None,
                false
            ),
            InputSource::MicroSd
        )
        .unwrap_err()
        .category,
        qk_psbt::RejectCategory::TooManyOutputs
    );
    for version in 0x52..=0x60 {
        for length in [2u8, 40] {
            let script = [vec![version, length], vec![1; usize::from(length)]].concat();
            reject(
                &psbt(&[(1, script)], None, false),
                SemanticCategory::FutureWitnessVersion,
            );
        }
    }
    let future = [vec![0x52, 2], vec![1, 2]].concat();
    reject(
        &psbt(&[(1, vec![0x61]), (1, future.clone())], None, false),
        SemanticCategory::UnsupportedRecipientScript,
    );
    reject(
        &psbt(&[(1, future), (1, vec![0x61])], None, false),
        SemanticCategory::FutureWitnessVersion,
    );
    // Every witness version is also exercised at all forbidden program
    // lengths, plus noncanonical and truncated push-looking spellings.
    for version in 0x00..=0x60 {
        if version != 0 && !(0x51..=0x60).contains(&version) {
            continue;
        }
        for length in [0u8, 1, 41] {
            let script = [vec![version, length], vec![1; usize::from(length)]].concat();
            reject(
                &psbt(&[(1, script)], None, false),
                SemanticCategory::MalformedWitnessProgram,
            );
        }
    }
    for (version, lengths) in [(0x00, [2u8, 19, 21, 33, 40]), (0x51, [2u8, 20, 31, 33, 40])] {
        for length in lengths {
            let script = [vec![version, length], vec![1; usize::from(length)]].concat();
            reject(
                &psbt(&[(1, script)], None, false),
                SemanticCategory::MalformedWitnessProgram,
            );
        }
    }
    reject(
        &psbt(
            &[(
                1,
                vec![0, 0x4c, 20]
                    .into_iter()
                    .chain(std::iter::repeat_n(1, 20))
                    .collect(),
            )],
            None,
            false,
        ),
        SemanticCategory::MalformedWitnessProgram,
    );
    reject(
        &psbt(&[(1, vec![0, 20, 1])], None, false),
        SemanticCategory::MalformedScriptPush,
    );
    let seed = psbt(
        &[(9000, hex("00141111111111111111111111111111111111111111"))],
        None,
        false,
    );
    assert!(seed.len() <= 4096);
    for i in 0..seed.len() {
        for m in [1, 0x80] {
            let mut x = seed.clone();
            x[i] ^= m;
            let original = x.clone();
            assert!(catch_unwind(AssertUnwindSafe(|| {
                if let Ok(v) = parse(&x, InputSource::MicroSd) {
                    let canonical = canonical_serialize(&v).unwrap();
                    let _ = analyze_recipient_script_facts(&v, &descriptor());
                    assert_eq!(canonical, canonical_serialize(&v).unwrap());
                }
            }))
            .is_ok());
            assert_eq!(x, original)
        }
    }
}
