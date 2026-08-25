use qk_a1::encrypt;
use qk_a1_codec::{encode, CodecProfile};
use std::io::Write;
use std::process::{Command, Output, Stdio};

const FIXTURE: &str = include_str!("../../qk-a1-codec/tests/fixtures/spike_reencode.txt");
const T0_PUBLIC_A2: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];
const GOLDEN_WALLET_ID: [u8; 32] = [
    0xa7, 0x98, 0x90, 0xdc, 0xde, 0x9c, 0x85, 0x17, 0xad, 0x86, 0x0a, 0xb3, 0xa9, 0x07, 0xff, 0x01,
    0x65, 0x2b, 0xbe, 0x20, 0x0a, 0x56, 0x10, 0x28, 0xce, 0xb6, 0x6e, 0x22, 0xe8, 0xc9, 0xd5, 0x43,
];

fn fixture_field(payload: &str, name: &str) -> &'static str {
    let marker = format!("payload={payload}\n");
    let block = FIXTURE
        .split("\n\n")
        .find(|block| block.starts_with(&marker))
        .expect("fixture payload");
    let prefix = format!("{name}=");
    block
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture field")
}

fn invoke(arguments: &[&str], transcription: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_qk-a1-smoke"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn smoke harness");
    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(transcription)
        .expect("write transcription");
    child.wait_with_output().expect("smoke harness output")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("ASCII stdout")
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut decoded = [0u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let pair = &value.as_bytes()[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
            .expect("fixture hex");
    }
    decoded
}

#[test]
fn all_three_exact_t0_transcriptions_authenticate() {
    for (payload, profile, expected_symbols) in [
        ("00", "Rs72_60", 116),
        ("01", "Rs76_60", 122),
        ("02", "Rs80_60", 128),
    ] {
        let token = fixture_field(payload, "token_ascii");
        let mut typed_line = token.as_bytes().to_vec();
        typed_line.extend_from_slice(if payload == "01" { b"\r\n" } else { b"\n" });
        let output = invoke(&[profile], &typed_line);
        assert!(output.status.success(), "{profile}: {}", stdout(&output));
        assert_eq!(
            stdout(&output),
            format!(
                "profile={profile} symbols={expected_symbols} erasure_symbols=0\n\
                 rs=PASS corrected_errors=0 erased_bytes=0\n\
                 aead=PASS\n\
                 fixture=PASS\n"
            )
        );
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn explicit_erasure_is_never_treated_as_a_guess() {
    let mut token = fixture_field("02", "token_ascii").as_bytes().to_vec();
    token[0] = b'?';
    let output = invoke(&["Rs80_60"], &token);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output),
        "profile=Rs80_60 symbols=128 erasure_symbols=1\n\
         rs=PASS corrected_errors=0 erased_bytes=1\n\
         aead=PASS\n\
         fixture=PASS\n"
    );
}

#[test]
fn known_symbol_error_is_corrected_and_reported() {
    let mut token = fixture_field("02", "token_ascii").as_bytes().to_vec();
    token[0] = if token[0] == b'2' { b'3' } else { b'2' };
    let output = invoke(&["Rs80_60"], &token);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output),
        "profile=Rs80_60 symbols=128 erasure_symbols=0\n\
         rs=PASS corrected_errors=1 erased_bytes=0\n\
         aead=PASS\n\
         fixture=PASS\n"
    );
}

#[test]
fn malformed_or_wrong_length_input_never_reaches_aead() {
    let token = fixture_field("00", "token_ascii");
    let short = invoke(&["Rs72_60"], &token.as_bytes()[..115]);
    assert_eq!(short.status.code(), Some(1));
    assert_eq!(
        stdout(&short),
        "input=FAIL error=InvalidSymbolCount expected=116 actual=115\n\
         rs=NOT_RUN\n\
         aead=NOT_RUN\n\
         fixture=NOT_RUN\n"
    );

    let mut malformed = token.as_bytes().to_vec();
    malformed[0] = b'A';
    let rejected = invoke(&["Rs72_60"], &malformed);
    assert_eq!(rejected.status.code(), Some(2));
    assert_eq!(
        stdout(&rejected),
        "profile=Rs72_60 symbols=116 erasure_symbols=0\n\
         rs=FAIL error=MalformedSymbol\n\
         aead=NOT_RUN\n\
         fixture=NOT_RUN\n"
    );

    let mut wrapped = token.as_bytes().to_vec();
    wrapped.insert(64, b'\n');
    let rejected_wrap = invoke(&["Rs72_60"], &wrapped);
    assert_eq!(rejected_wrap.status.code(), Some(1));
    assert!(stdout(&rejected_wrap)
        .starts_with("input=FAIL error=InvalidSymbolCount expected=116 actual=64\n"));

    let mut bare_carriage_return = token.as_bytes().to_vec();
    bare_carriage_return.push(b'\r');
    let rejected_carriage_return = invoke(&["Rs72_60"], &bare_carriage_return);
    assert_eq!(rejected_carriage_return.status.code(), Some(1));
    assert!(stdout(&rejected_carriage_return).starts_with(
        "input=FAIL error=EmbeddedLineBreak\nrs=NOT_RUN\naead=NOT_RUN\nfixture=NOT_RUN\n"
    ));

    let overflow = invoke(&["Rs80_60"], &[b'2'; 129]);
    assert_eq!(overflow.status.code(), Some(1));
    assert!(stdout(&overflow)
        .starts_with("input=FAIL error=InputTooLong\nrs=NOT_RUN\naead=NOT_RUN\nfixture=NOT_RUN\n"));
}

#[test]
fn overcapacity_erasures_stop_before_aead() {
    let output = invoke(&["Rs72_60"], &[b'?'; 116]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        stdout(&output),
        "profile=Rs72_60 symbols=116 erasure_symbols=116\n\
         rs=FAIL error=OverCapacity\n\
         aead=NOT_RUN\n\
         fixture=NOT_RUN\n"
    );
}

#[test]
fn aead_and_exact_fixture_failures_are_separated() {
    let mut capsule = decode_hex::<67>(fixture_field("02", "capsule_hex"));
    capsule[66] ^= 1;
    let mut token = [0u8; 128];
    encode(CodecProfile::Rs80_60, &capsule, &mut token).expect("fixture re-encode");
    let output = invoke(&["Rs80_60"], &token);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        stdout(&output),
        "profile=Rs80_60 symbols=128 erasure_symbols=0\n\
         rs=PASS corrected_errors=0 erased_bytes=0\n\
         aead=FAIL error=AuthenticationFailed\n\
         fixture=NOT_RUN\n"
    );

    let alternate = encrypt(&T0_PUBLIC_A2, &GOLDEN_WALLET_ID, &[0x44; 12], &[0x55; 32]);
    encode(CodecProfile::Rs80_60, &alternate, &mut token).expect("public alternate encode");
    let fixture_rejected = invoke(&["Rs80_60"], &token);
    assert_eq!(fixture_rejected.status.code(), Some(4));
    assert_eq!(
        stdout(&fixture_rejected),
        "profile=Rs80_60 symbols=128 erasure_symbols=0\n\
         rs=PASS corrected_errors=0 erased_bytes=0\n\
         aead=PASS\n\
         fixture=FAIL error=UnexpectedT0Fixture\n"
    );
}

#[test]
fn output_never_echoes_fixture_material_and_profiles_have_no_default() {
    let token = fixture_field("00", "token_ascii");
    let output = invoke(&["Rs72_60"], token.as_bytes());
    assert!(output.status.success());
    let visible = stdout(&output);
    for forbidden in [
        token,
        fixture_field("00", "capsule_hex"),
        fixture_field("00", "public_seed_a_hex"),
        fixture_field("00", "public_a2_hex"),
        fixture_field("00", "wallet_id_hex"),
    ] {
        assert!(!visible.contains(forbidden));
    }

    for arguments in [&[][..], &["unknown"][..], &["Rs72_60", "extra"][..]] {
        let usage = invoke(arguments, b"");
        assert_eq!(usage.status.code(), Some(64));
        assert!(usage.stdout.is_empty());
        assert!(String::from_utf8(usage.stderr)
            .expect("ASCII stderr")
            .starts_with("usage: qk-a1-smoke "));
    }
}
