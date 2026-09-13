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

fn altered_first_sign(
    mut mutate: impl FnMut(&mut Vec<u8>),
) -> (Sec1210FidiSignSummary, String, Vec<Vec<u8>>, usize) {
    let mut sign_count = 0;
    let mut reader = Reader::new(|request: &[u8], response: &mut Vec<u8>| {
        if request[1] == 0x15 {
            sign_count += 1;
            if sign_count == 1 {
                mutate(response);
            } else {
                // End the test after the real verifier accepts the first
                // signature; do not bless its deterministic repeated r.
                *response.last_mut().unwrap() = 1;
            }
        }
    });
    let (summary, transcript) = run(&mut reader);
    (summary, transcript, reader.responses, reader.writes.len())
}

#[test]
fn sign_binding_rejections_precede_real_curve_verification_and_stop_writes() {
    for (offset, expected) in [
        (0, "B6ResponseVersionMismatch"),
        (1, "B6ResponseSessionMismatch"),
        (20, "B6ResponseCounterMismatch"),
        (21, "B6ResponseReviewHashMismatch"),
        (56, "B6ResponseInputIndexMismatch"),
        (57, "B6ResponseKeyMismatch"),
        (90, "B6ResponseDerLengthMismatch"),
    ] {
        let (summary, transcript, responses, writes) =
            altered_first_sign(|response| response[offset] ^= 1);
        assert_eq!(summary.failure.unwrap().name(), expected, "{transcript}");
        assert_eq!(writes, 8);
        assert_eq!(summary.signature_fact_count, 0);
        assert_eq!(summary.signature_accepted_count, 0);
        assert!(summary.local_handle_released);
        assert!(transcript.contains(&hex(responses.last().unwrap())));
        assert!(!transcript.contains("command.9.request_hex="));
    }
}

#[test]
fn status_has_precedence_and_full_hostile_reply_remains_in_transcript() {
    let (summary, transcript, responses, writes) = altered_first_sign(|response| {
        *response.last_mut().unwrap() = 1;
        response[0] = 99;
        response[57] = 99;
    });
    assert_eq!(summary.failure.unwrap().name(), "B6StatusRejected");
    assert_eq!(writes, 8);
    assert_eq!(summary.signature_fact_count, 0);
    assert!(transcript.contains(&hex(responses.last().unwrap())));
}

#[test]
fn deterministic_valid_golden_signature_verifies_then_repeated_r_is_terminal() {
    let mut reader = Reader::new(|_: &[u8], _: &mut Vec<u8>| {});
    let (summary, transcript) = run(&mut reader);
    assert_eq!(
        summary.failure.unwrap().name(),
        "B6RepeatedR",
        "{transcript}"
    );
    assert_eq!(summary.signature_fact_count, 2);
    assert_eq!(summary.signature_accepted_count, 1);
    assert_eq!(summary.normalization_changed_count, 0);
    assert_eq!(summary.completed_sessions, 0);
    assert_eq!(reader.writes.len(), 9);
    assert_eq!(reader.responses.len(), 4);
    assert!(summary.local_handle_released);
    assert!(transcript.contains(&hex(reader.responses.last().unwrap())));
    assert!(!transcript.contains("command.10.request_hex="));
}

#[test]
fn high_s_and_low_s_use_real_normalization_and_real_verification() {
    let raw = golden_response();
    let low_der = &raw[91..raw.len() - 2];
    let mut high = vec![0x30, 0x46, 2, 0x21];
    high.extend_from_slice(&low_der[4..37]);
    high.extend_from_slice(&[2, 0x21, 0]);
    high.extend_from_slice(&decode(
        "bf61fc4abd1a78f9fa367c00a6442598aebf994ca058bf34e8a747b94a49ad0a",
    ));
    let key = qk_secp::pubkey_parse_compressed(&B6_PUBLIC_KEY).unwrap();
    assert!(qk_secp::ecdsa_verify(
        &qk_secp::signature_parse_der(&high).unwrap(),
        &B6_DIGEST,
        &key
    )
    .is_err());
    let (low, low_text, _, low_writes) = altered_first_sign(|_| {});
    let (high_summary, high_text, _, high_writes) = altered_first_sign(|response| {
        response.truncate(91);
        response[90] = high.len() as u8;
        response.extend_from_slice(&high);
        response.extend_from_slice(&[0x90, 0]);
    });
    for (summary, writes, text) in [
        (&low, low_writes, &low_text),
        (&high_summary, high_writes, &high_text),
    ] {
        assert_eq!(
            summary.failure.unwrap().name(),
            "B6StatusRejected",
            "{text}"
        );
        assert_eq!(summary.signature_accepted_count, 1);
        assert_eq!(summary.signature_fact_count, 1);
        assert_eq!(writes, 9);
    }
    assert_eq!(low.normalization_changed_count, 0);
    assert_eq!(high_summary.normalization_changed_count, 1);
    assert!(high_text.contains(&hex(&high)));
}

#[test]
fn malformed_nonminimal_overlong_der_and_invalid_curve_value_are_distinct() {
    for der in [
        vec![0x31, 6, 2, 1, 1, 2, 1, 1],
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
        vec![0x30, 0x81, 6, 2, 1, 1, 2, 1, 1],
    ] {
        let (summary, transcript, responses, writes) = altered_first_sign(|response| {
            response.truncate(91);
            response[90] = der.len() as u8;
            response.extend_from_slice(&der);
            response.extend_from_slice(&[0x90, 0]);
        });
        assert_eq!(
            summary.failure.unwrap().name(),
            "B6DerRejected",
            "{transcript}"
        );
        assert_eq!(summary.signature_fact_count, 0);
        assert_eq!(writes, 8);
        assert!(transcript.contains(&hex(responses.last().unwrap())));
    }
    let (summary, transcript, _, writes) = altered_first_sign(|response| {
        let last_s_byte = response.len() - 3;
        response[last_s_byte] ^= 1;
    });
    assert_eq!(
        summary.failure.unwrap().name(),
        "B6SignatureVerificationFailed",
        "{transcript}"
    );
    assert_eq!(summary.signature_fact_count, 1);
    assert_eq!(summary.signature_accepted_count, 0);
    assert_eq!(writes, 8);
}

#[test]
fn truncated_excess_or_inconsistent_signature_tails_are_named() {
    for (kind, expected) in [
        (0, "B6ResponseLengthMismatch"),
        (1, "B6ResponseLimitExceeded"),
        (2, "B6ResponseDerLengthMismatch"),
    ] {
        let (summary, transcript, _, writes) = altered_first_sign(|response| match kind {
            0 => *response = vec![0x90, 0],
            1 => {
                response.resize(219, 0);
                response[217..].copy_from_slice(&[0x90, 0]);
            }
            _ => response.insert(response.len() - 2, 0),
        });
        assert_eq!(summary.failure.unwrap().name(), expected, "{transcript}");
        assert_eq!(summary.signature_fact_count, 0);
        assert_eq!(writes, 8);
    }
}

#[test]
fn exact_select_and_open_acceptance_precede_every_sign() {
    for (instruction, offset, expected) in [
        (0xa4, 0, "B6ResponseLengthMismatch"),
        (0x10, 0, "B6ResponseVersionMismatch"),
        (0x10, 1, "B6ResponseSessionMismatch"),
        (0x10, 20, "B6ResponseCounterMismatch"),
    ] {
        let mut reader = Reader::new(|request: &[u8], response: &mut Vec<u8>| {
            if request[1] == instruction {
                if instruction == 0xa4 {
                    response.insert(0, 0);
                } else {
                    response[offset] ^= 1;
                }
            }
        });
        let (summary, transcript) = run(&mut reader);
        assert_eq!(summary.failure.unwrap().name(), expected, "{transcript}");
        assert_eq!(summary.signature_fact_count, 0);
        assert_eq!(reader.writes.len(), if instruction == 0xa4 { 6 } else { 7 });
        assert!(!transcript.contains("command.8.request_hex="));
    }
}

#[test]
fn later_release_failure_does_not_replace_original_signature_rejection() {
    let mut reader = Reader::new(|request: &[u8], response: &mut Vec<u8>| {
        if request[1] == 0x15 {
            response[1] ^= 1;
        }
    });
    reader.release_failure = true;
    let (summary, transcript) = run(&mut reader);
    assert_eq!(
        summary.failure.unwrap().name(),
        "B6ResponseSessionMismatch",
        "{transcript}"
    );
    assert_eq!(reader.writes.len(), 8);
    assert_eq!(summary.signature_fact_count, 0);
}
