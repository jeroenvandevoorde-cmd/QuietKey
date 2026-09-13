use qk_card_enrollment::*;
use std::collections::VecDeque;

const UTC: &str = "2026-09-14T00:00:00Z";
const GOLDEN: &str =
    include_str!("../../../host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

fn decode(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}

fn golden_response() -> Vec<u8> {
    decode(
        GOLDEN
            .lines()
            .find_map(|line| line.strip_prefix("normal_sign_0_response_hex: "))
            .unwrap(),
    )
}

fn response_for(request: &[u8]) -> Vec<u8> {
    match request[1] {
        0xa4 => vec![0x90, 0],
        0x10 => {
            let mut response = vec![1];
            response.extend_from_slice(&request[7..23]);
            response.extend_from_slice(&[0, 0, 0, 0, 0x90, 0]);
            response
        }
        0x15 => {
            // Only public session/index echoes change. The deterministic
            // GOLDEN signature and its key/digest remain the registered pair.
            let mut response = golden_response();
            response[..21].copy_from_slice(&request[5..26]);
            response[53..57].copy_from_slice(&request[90..94]);
            response
        }
        _ => panic!("unexpected fixed application command"),
    }
}

fn block(pcb: u8, inf: &[u8]) -> Vec<u8> {
    assert!(inf.len() <= 254);
    let mut bytes = vec![0, pcb, inf.len() as u8];
    bytes.extend_from_slice(inf);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

fn ccid(kind: u8, sequence: u8, status: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![3, 6, kind];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0, sequence, status, 0, parameter]);
    bytes.extend_from_slice(payload);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

struct Reader<F> {
    mutate: F,
    writes: Vec<Vec<u8>>,
    responses: Vec<Vec<u8>>,
    reads: VecDeque<Vec<u8>>,
    now: u64,
    sent_at: u64,
    opened: bool,
    release_failure: bool,
}

impl<F: FnMut(&[u8], &mut Vec<u8>)> Reader<F> {
    fn new(mutate: F) -> Self {
        Self {
            mutate,
            writes: Vec::new(),
            responses: Vec::new(),
            reads: VecDeque::new(),
            now: 0,
            sent_at: 0,
            opened: false,
            release_failure: false,
        }
    }

    fn reply(&mut self, request: &[u8]) -> Vec<u8> {
        let ordinal = self.writes.len() + 1;
        assert_eq!(request.iter().fold(0, |sum, byte| sum ^ byte), 0);
        assert_eq!(request[8], ordinal as u8);
        match ordinal {
            1 => {
                assert_eq!(request, decode("03066500000000000100000061"));
                ccid(0x81, 1, 1, 1, &[])
            }
            2 => {
                assert_eq!(request, decode("03066200000000000202000067"));
                ccid(0x80, 2, 0, 0, &qk_sec1210_wire::REGISTERED_ATR)
            }
            3 => {
                assert_eq!(request, decode("03066c0000000000030000006a"));
                ccid(0x82, 3, 0, 1, &decode("1110ff4d00fe00"))
            }
            4 => {
                assert_eq!(request, decode("0306610700000000040100001810ff4d00fe0022"));
                ccid(0x82, 4, 0, 1, &decode("1810ff4d00fe00"))
            }
            5 => {
                assert_eq!(request, decode("03066f05000000000500000000c101fe3e6a"));
                ccid(0x80, 5, 0, 0, &decode("00e101fe1e"))
            }
            _ => {
                assert_eq!(request[2], 0x6f);
                assert_eq!(&request[9..12], [0, 0, 0]);
                let tpdu = &request[12..request.len() - 1];
                assert_eq!(tpdu.iter().fold(0, |sum, byte| sum ^ byte), 0);
                assert_eq!(usize::from(tpdu[2]) + 4, tpdu.len());
                let position = self.responses.len();
                assert_eq!(tpdu[1], (position as u8 % 2) << 6);
                let apdu = &tpdu[3..tpdu.len() - 1];
                assert_eq!(apdu, b6_exchange(0, position).unwrap().request());
                let mut response = response_for(apdu);
                (self.mutate)(apdu, &mut response);
                self.responses.push(response.clone());
                ccid(0x80, ordinal as u8, 0, 0, &block(tpdu[1], &response))
            }
        }
    }
}

impl<F: FnMut(&[u8], &mut Vec<u8>)> Sec1210Transport for Reader<F> {
    fn configure(&mut self) -> Result<i32, Sec1210Error> {
        Ok(0)
    }
    fn open(&mut self) -> Result<(), Sec1210Error> {
        self.opened = true;
        Ok(())
    }
    fn write_once(&mut self, request: &[u8]) -> Result<usize, Sec1210Error> {
        assert!(self.opened);
        assert!(
            self.reads.is_empty(),
            "the preceding response must be consumed"
        );
        let response = self.reply(request);
        self.reads.extend(response.chunks(8).map(<[u8]>::to_vec));
        self.writes.push(request.to_vec());
        self.sent_at = self.now;
        Ok(request.len())
    }
    fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
        self.now += 10;
        Ok(())
    }
    fn read(&mut self, _: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
        panic!("the SIGN engine must use the deadline-aware read path")
    }
    fn release(&mut self) -> Result<bool, Sec1210Error> {
        let opened = self.opened;
        self.opened = false;
        if self.release_failure {
            Err(Sec1210Error::CloseFailed)
        } else {
            Ok(opened)
        }
    }
}

impl<F: FnMut(&[u8], &mut Vec<u8>)> Sec1210FidiSignTransport for Reader<F> {
    fn now_ms(&mut self) -> u64 {
        self.now
    }
    fn utc_now(&mut self) -> Result<String, Sec1210FidiSignError> {
        Ok(UTC.into())
    }
    fn read_until(
        &mut self,
        buffer: &mut [u8],
        deadline_ms: u64,
    ) -> Result<(usize, u64), Sec1210Error> {
        assert!(self.now < deadline_ms);
        let bytes = self.reads.pop_front().unwrap_or_default();
        self.now += if bytes.is_empty() { 5000 } else { 1 };
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), self.now - self.sent_at))
    }
}

fn run<F: FnMut(&[u8], &mut Vec<u8>)>(reader: &mut Reader<F>) -> (Sec1210FidiSignSummary, String) {
    let metadata = Sec1210FidiSignMetadata::new(
        "a".repeat(40),
        UTC.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_fidi_sign_output_basename(UTC)),
    )
    .unwrap();
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    let summary = run_sec1210_fidi_sign(&metadata, reader, &mut transcript);
    (summary, String::from_utf8(transcript.into_inner()).unwrap())
}

#[test]
fn subset_plan_is_b6_session_zero_with_exact_identity() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut bytes = Vec::new();
    for position in 0..102 {
        let exchange = b6_exchange(0, position).unwrap();
        bytes.extend_from_slice(exchange.request());
        match qk_card_protocol::parse_command(
            qk_card_protocol::Media::ContactT1,
            exchange.request(),
        )
        .unwrap()
        {
            qk_card_protocol::CommandRef::Select => assert_eq!(position, 0),
            qk_card_protocol::CommandRef::OpenSession { session_id, mode } => {
                assert_eq!(position, 1);
                assert_eq!(session_id, &B6_SESSION_IDS[0]);
                assert_eq!(mode, qk_card_protocol::Mode::Normal);
            }
            qk_card_protocol::CommandRef::SignDigest {
                envelope,
                wallet_id,
                review_hash,
                input_index,
                branch,
                child_index,
                digest,
            } => {
                assert_eq!(envelope.session_id(), &[0xc0; 16]);
                assert_eq!(envelope.sequence(), (position - 1) as u32);
                assert_eq!(input_index, (position - 2) as u32);
                assert_eq!(wallet_id, &B6_WALLET_ID);
                assert_eq!(review_hash, &B6_REVIEW_HASH);
                assert_eq!((branch, child_index), (0, 0));
                assert_eq!(digest, &B6_DIGEST);
            }
            _ => panic!("fixed SIGN session contains no other operation"),
        }
    }
    assert_eq!(bytes.len(), FIDI_SIGN_PLAN_BYTES);
    assert_eq!(FIDI_SIGN_PLAN_BYTES, 13236);
    // A separately written encoder uses literal grammar and literal public
    // GOLDEN fields, without calling either protocol or B6 constructors.
    let mut independent = decode("00a4040006f0514b32420100");
    independent.extend_from_slice(&decode("80100000120102"));
    independent.extend_from_slice(&[0xc0; 16]);
    independent.push(0);
    for index in 0u32..100 {
        independent.extend_from_slice(&[0x80, 0x15, 0, 0, 126, 1]);
        independent.extend_from_slice(&[0xc0; 16]);
        independent.extend_from_slice(&(index + 1).to_be_bytes());
        independent.extend_from_slice(&decode(
            "d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e",
        ));
        independent.extend_from_slice(&decode(
            "9c5de46f2ac5f29f6c9335b4016b65fe96aa0cd04e3a6b5b7224389db5fae3a3",
        ));
        independent.extend_from_slice(&index.to_be_bytes());
        independent.extend_from_slice(&[0; 5]);
        independent.extend_from_slice(&decode(
            "0d3d0763b43943f0f5342003355f8359fff4ba942dae2286becc635dc88d8386",
        ));
        independent.push(0);
    }
    assert_eq!(bytes, independent);
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next(),
        Some(FIDI_SIGN_PLAN_SHA256)
    );
    assert_eq!(
        FIDI_SIGN_PLAN_SHA256,
        "ad0ffd7e79ebb8500a4f94a5f06aa527ec59537a59923956170f45cfdbdf3659"
    );
}

fn model_reader() -> Reader<impl FnMut(&[u8], &mut Vec<u8>)> {
    let mut model = qk_card_model::CardModel::new();
    let plan = fixed_sitting_plan(SittingMode::ProvisionGolden).unwrap();
    for exchange in plan.exchanges() {
        let mut output = [0u8; qk_card_model::RESPONSE_BYTES];
        let length = model
            .process_apdu(
                qk_card_protocol::Media::ContactT1,
                exchange.request(),
                &mut output,
            )
            .unwrap();
        assert_eq!(&output[..length], exchange.expected_response());
    }
    Reader::new(move |request: &[u8], response: &mut Vec<u8>| {
        let mut output = [0u8; qk_card_model::RESPONSE_BYTES];
        let length = model
            .process_apdu(qk_card_protocol::Media::ContactT1, request, &mut output)
            .unwrap();
        response.clear();
        response.extend_from_slice(&output[..length]);
    })
}

#[test]
fn actual_committed_card_model_second_signature_is_terminal_repeated_r() {
    let mut reader = model_reader();
    let (summary, text) = run(&mut reader);
    assert_eq!(summary.failure.unwrap().name(), "B6RepeatedR");
    assert_eq!(summary.signature_fact_count, 2);
    assert_eq!(summary.signature_accepted_count, 1);
    assert_eq!(summary.completed_sessions, 0);
    assert_eq!((summary.request_count, summary.response_count), (9, 9));
    assert_eq!(reader.responses.len(), 4);
    assert!(text.contains("apdu.2.verify=PASS\n"));
    assert!(text.contains("apdu.3.verify=PASS\n"));
    assert!(text.contains(&format!("apdu.3.rx_hex={}\n", hex(&reader.responses[3]))));
    assert!(!text.contains("apdu.4.tx_hex="));
}

#[test]
fn actual_model_mock_transcript_reconstructs_exactly_from_public_inputs() {
    let (a, text) = run(&mut model_reader());
    let (b, replay) = run(&mut model_reader());
    assert_eq!(a, b);
    assert_eq!(text, replay);
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("session.0.start_utc="))
            .count(),
        1
    );
    assert!(text.contains("first_failure=B6RepeatedR\n"));
    assert!(text.contains("local_handle_released=PASS\n"));
}
