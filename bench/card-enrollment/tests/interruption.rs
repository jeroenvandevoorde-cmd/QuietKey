use std::cell::{Cell, RefCell};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;

use qk_card_enrollment::*;
use qk_card_model::{CardModel, RESPONSE_BYTES};
use qk_card_protocol::Media;

const UTC: &str = "2026-09-08T20:00:00Z";
const TRIALS: [InterruptionTrial; 4] = [
    InterruptionTrial::UnpowerFinalWrite,
    InterruptionTrial::UnpowerSecondWrite,
    InterruptionTrial::RemoveCommit1,
    InterruptionTrial::RemoveCommit2,
];
const MODES: [InterruptionMode; 3] = [
    InterruptionMode::InterruptGolden,
    InterruptionMode::ClassifyGolden,
    InterruptionMode::AbortStagingGolden,
];
fn metadata(mode: InterruptionMode, trial: InterruptionTrial) -> InterruptionMetadata {
    let enrollment = EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: SITTING_CAMPAIGN_SOURCE_COMMIT.into(),
        timestamp_utc: UTC.into(),
        host_alias: "iMac".into(),
        reader_alias: "SCR3310-01".into(),
        specimen_alias: Some("J3R180-03".into()),
        selected_reader_name: Some(SITTING_READER_NAME.to_vec()),
    }
    .validate()
    .unwrap();
    let path = PathBuf::from("/tmp").join(interruption_output_basename(mode, trial, UTC));
    let wait = removal_wait_for(mode, trial, || Some(OsString::from("12345"))).unwrap();
    InterruptionMetadata::new(mode, trial, enrollment, path, wait).unwrap()
}
fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn row(branch: &str, index: usize) -> InterruptionPlanRow {
    interruption_plan()
        .unwrap()
        .into_iter()
        .find(|r| r.branch == branch && r.index == index)
        .unwrap()
}

#[test]
fn fixture_identity_and_prefixes_are_byte_frozen() {
    assert_eq!(INTERRUPTION_PLAN.len(), 13_506);
    assert_eq!(
        INTERRUPTION_PLAN.bytes().filter(|b| *b == b'\n').count(),
        57
    );
    assert_eq!(INTERRUPTION_PLAN_BYTES, 13_506);
    assert_eq!(INTERRUPTION_PLAN_LF, 57);
    let mut hash = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hash.stdin
        .take()
        .unwrap()
        .write_all(INTERRUPTION_PLAN.as_bytes())
        .unwrap();
    let output = hash.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next(),
        Some(INTERRUPTION_PLAN_SHA256)
    );
    assert_eq!(
        INTERRUPTION_PLAN_SHA256,
        "48c57da772e4e57e955add911e528403881e211eabb37743d5bd59ed6c075cbc"
    );
    let provision = fixed_sitting_plan(SittingMode::ProvisionGolden).unwrap();
    for (trial, count) in TRIALS.into_iter().zip([8, 5, 9, 9]) {
        let rows: Vec<_> = interruption_plan()
            .unwrap()
            .into_iter()
            .filter(|r| r.branch == trial.as_str())
            .collect();
        assert_eq!(rows.len(), count);
        for (r, p) in rows.iter().zip(provision.exchanges()) {
            assert_eq!(decode(r.request_hex), p.request());
            assert_eq!(decode(r.response_hex), p.expected_response());
        }
    }
    for r in interruption_plan().unwrap() {
        assert_ne!(decode(r.request_hex)[1], 0x15);
        assert!(r.request_hex.len() / 2 <= 221);
        assert!(r.response_hex.len() / 2 <= 218);
    }
}

#[test]
fn classifier_construction_pins_all_bytes_not_just_lifecycle() {
    for (branch, counter) in [
        ("classifier-7", 7u32),
        ("classifier-4", 4),
        ("classifier-8", 8),
    ] {
        let mut stale = vec![0x80, 0x11, 0, 0, 21, 1];
        stale.extend([0xa1; 16]);
        stale.extend(counter.to_be_bytes());
        stale.push(0);
        assert_eq!(decode(row(branch, 1).request_hex), stale);
        assert_eq!(decode(row(branch, 1).response_hex), [0x6f, 3]);
        assert_eq!(row(branch, 0).request_hex, row(branch, 2).request_hex);
    }
    for (branch, life, mask) in [
        ("info-unprovisioned", 0, 0x11u16),
        ("info-staging-incomplete", 1, 0xb1),
        ("info-staging-complete", 1, 0xd1),
    ] {
        let mut response = vec![1];
        response.extend([0xb2; 16]);
        response.extend(1u32.to_be_bytes());
        response.extend([1, 1, life, 0, 2]);
        response.extend([0; 130]);
        response.extend(mask.to_be_bytes());
        response.extend([0x90, 0]);
        assert_eq!(decode(row(branch, 4).response_hex), response);
    }
}

#[derive(Clone)]
enum Injection {
    Bytes(Vec<u8>),
    Failure(InterruptionError),
    Panic,
    Excess,
}
struct Mock {
    model: CardModel,
    connected: bool,
    calls: Vec<Vec<u8>>,
    operations: Vec<&'static str>,
    inject: Option<(usize, Injection)>,
    rollback_commit: bool,
    wait: Result<pcsc::State, InterruptionError>,
    timeout: Option<u32>,
    disconnect_failure: bool,
    flushed: Option<Rc<RefCell<Vec<u8>>>>,
}
impl Default for Mock {
    fn default() -> Self {
        Self {
            model: CardModel::new(),
            connected: false,
            calls: Vec::new(),
            operations: Vec::new(),
            inject: None,
            rollback_commit: false,
            wait: Ok(pcsc::State::EMPTY | pcsc::State::CHANGED),
            timeout: None,
            disconnect_failure: false,
            flushed: None,
        }
    }
}
impl InterruptionBackend for Mock {
    fn establish_context(&mut self) -> Result<(), InterruptionError> {
        self.operations.push("context");
        Ok(())
    }
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, InterruptionError> {
        Ok(vec![SITTING_READER_NAME.to_vec()])
    }
    fn connect_exclusive(&mut self) -> Result<(), InterruptionError> {
        self.operations.push("connect");
        self.connected = true;
        Ok(())
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
    fn capture_status(&mut self) -> Result<ObservationStatus, InterruptionError> {
        Ok(ObservationStatus {
            atr: REGISTERED_J3R180_ATR.to_vec(),
            protocol: Some(NegotiatedProtocol::T1),
        })
    }
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_SITTING_CAPTURE_BYTES],
    ) -> Result<usize, InterruptionError> {
        if let Some(bytes) = &self.flushed {
            let expected = format!(".tx_hex={}\n", hex(request));
            assert!(
                bytes.borrow().ends_with(expected.as_bytes()),
                "request must be flushed before transmit"
            );
        }
        let position = self.calls.len();
        self.calls.push(request.to_vec());
        self.operations.push("exchange");
        if let Some((index, injection)) = &self.inject {
            if position == *index {
                match injection {
                    Injection::Bytes(bytes) => {
                        response[..bytes.len()].copy_from_slice(bytes);
                        return Ok(bytes.len());
                    }
                    Injection::Failure(error) => return Err(*error),
                    Injection::Panic => panic!("caught boundary probe"),
                    Injection::Excess => return Ok(MAX_SITTING_CAPTURE_BYTES + 1),
                }
            }
        }
        if self.rollback_commit && request[1] == 0x22 {
            self.model.deselect();
            return Err(InterruptionError::Native(pcsc::Error::RemovedCard));
        }
        let mut output = [0; RESPONSE_BYTES];
        let n = self
            .model
            .process_apdu(Media::ContactT1, request, &mut output)
            .unwrap_or(2);
        response[..n].copy_from_slice(&output[..n]);
        output.fill(0);
        Ok(n)
    }
    fn unpower(&mut self) -> Result<(), InterruptionError> {
        self.operations.push("unpower");
        self.model.deselect();
        self.connected = false;
        Ok(())
    }
    fn signal_removal(&mut self) -> Result<(), InterruptionError> {
        self.operations.push("signal");
        Ok(())
    }
    fn wait_removal(&mut self, timeout: RemovalWaitMs) -> Result<pcsc::State, InterruptionError> {
        self.operations.push("wait");
        self.timeout = Some(timeout.get());
        self.model.deselect();
        self.wait
    }
    fn disconnect_leave_card(&mut self) -> Result<(), InterruptionError> {
        self.operations.push("leave");
        self.connected = false;
        if self.disconnect_failure {
            Err(SittingError::SittingDisconnectFailed.into())
        } else {
            Ok(())
        }
    }
}

struct FlushedWriter {
    pending: Vec<u8>,
    flushed: Rc<RefCell<Vec<u8>>>,
    count: Rc<Cell<usize>>,
}
impl Write for FlushedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushed.borrow_mut().append(&mut self.pending);
        self.count.set(self.count.get() + 1);
        Ok(())
    }
}

#[test]
fn request_flush_precedes_every_transmit_and_unknown_info_bytes_are_retained() {
    let bytes = Rc::new(RefCell::new(Vec::new()));
    let count = Rc::new(Cell::new(0));
    let mut m = Mock {
        flushed: Some(bytes.clone()),
        inject: Some((4, Injection::Bytes(vec![0x6a, 0x80]))),
        ..Mock::default()
    };
    let mut t = InterruptionTranscript::new(FlushedWriter {
        pending: Vec::new(),
        flushed: bytes.clone(),
        count: count.clone(),
    });
    let s = run_interruption(&metadata(MODES[1], TRIALS[0]), &mut m, &mut t);
    assert_eq!(
        s.outcome,
        InterruptionOutcome::Reject(InterruptionError::InfoRejected)
    );
    let text = String::from_utf8(bytes.borrow().clone()).unwrap();
    assert!(
        text.find("apdu.4.rx_hex=6a80").unwrap()
            < text
                .find("apdu.4.comparison=InterruptionInfoRejected")
                .unwrap()
    );
    assert!(count.get() > s.transmit_calls * 3);
    assert_eq!(m.calls.len(), 5);
}

#[test]
fn new_mode_binding_excludes_protected_and_iteration_specimens_and_output_substitution() {
    let original = metadata(MODES[1], TRIALS[0]);
    for specimen in ["J3R180-01", "J3R180-02"] {
        let enrollment = EnrollmentMetadata {
            mode: EnrollmentMode::Enroll,
            source_commit: SITTING_CAMPAIGN_SOURCE_COMMIT.into(),
            timestamp_utc: UTC.into(),
            host_alias: "iMac".into(),
            reader_alias: "SCR3310-01".into(),
            specimen_alias: Some(specimen.into()),
            selected_reader_name: Some(SITTING_READER_NAME.to_vec()),
        }
        .validate()
        .unwrap();
        assert_eq!(
            InterruptionMetadata::new(
                MODES[1],
                TRIALS[0],
                enrollment,
                original.output_path().to_path_buf(),
                None
            ),
            Err(SittingError::SittingBindingMismatch.into())
        );
    }
    assert_eq!(
        InterruptionMode::parse("custom"),
        Err(InterruptionError::ModeRejected)
    );
    assert_eq!(
        InterruptionTrial::parse("offset-3"),
        Err(InterruptionError::TrialRejected)
    );
}
fn run(
    mode: InterruptionMode,
    trial: InterruptionTrial,
    m: &mut Mock,
) -> (InterruptionSummary, String) {
    let mut t = InterruptionTranscript::new(Vec::new());
    let summary = run_interruption(&metadata(mode, trial), m, &mut t);
    let text = String::from_utf8(t.into_inner()).unwrap();
    assert!(text.len() <= 32768);
    (summary, text)
}

#[test]
fn both_write_cuts_classify_abort_and_complete_the_same_golden_record() {
    for (trial, state, count) in [
        (TRIALS[0], RawCardState::StagingComplete, 8),
        (TRIALS[1], RawCardState::StagingIncomplete, 5),
    ] {
        let mut m = Mock::default();
        let (s, text) = run(MODES[0], trial, &mut m);
        assert_eq!(s.outcome, InterruptionOutcome::Interrupted);
        assert_eq!(s.transmit_calls, count);
        assert_eq!(m.operations.last(), Some(&"unpower"));
        assert_eq!(m.timeout, None);
        assert!(text.contains("physical effect unproven"));
        assert!(!text.contains("result=PASS"));
        let (s, text) = run(MODES[1], trial, &mut m);
        assert_eq!(s.outcome, InterruptionOutcome::Classified(state));
        assert!(text.contains("old session rejected after reselection"));
        assert_eq!(s.transmit_calls, 5);
        let (s, _) = run(MODES[2], trial, &mut m);
        assert_eq!(s.outcome, InterruptionOutcome::RecoveredUnprovisioned);
        assert_eq!(s.transmit_calls, 9);
        for exchange in fixed_sitting_plan(SittingMode::ProvisionGolden)
            .unwrap()
            .exchanges()
        {
            let mut output = [0; RESPONSE_BYTES];
            let n = m
                .model
                .process_apdu(Media::ContactT1, exchange.request(), &mut output)
                .unwrap();
            assert_eq!(&output[..n], exchange.expected_response());
        }
    }
}

#[test]
fn removal_trials_keep_both_commit_outcomes_and_never_send_a_later_apdu() {
    for trial in [TRIALS[2], TRIALS[3]] {
        for rollback in [false, true] {
            let mut m = Mock {
                rollback_commit: rollback,
                ..Mock::default()
            };
            let (s, text) = run(MODES[0], trial, &mut m);
            assert_eq!(s.outcome, InterruptionOutcome::Interrupted);
            assert_eq!(s.transmit_calls, 9);
            assert_eq!(s.received_responses, if rollback { 8 } else { 9 });
            assert_eq!(m.timeout, Some(12345));
            assert!(text.contains("removal_wait_ms=12345\n"));
            assert!(text.contains("removal_event_state=0x12\n"));
            let signal = m.operations.iter().position(|v| *v == "signal").unwrap();
            assert_eq!(
                &m.operations[signal..],
                ["signal", "exchange", "wait", "leave"]
            );
            if rollback {
                assert!(text.contains("commit_response=ABSENT"));
            } else {
                assert!(text.contains(&format!(
                    "apdu.8.rx_hex={}\n",
                    row(trial.as_str(), 8).response_hex
                )));
            }
            let (s, _) = run(MODES[1], trial, &mut m);
            assert_eq!(
                s.outcome,
                InterruptionOutcome::Classified(if rollback {
                    RawCardState::StagingComplete
                } else {
                    RawCardState::CommittedGolden
                })
            );
        }
    }
}

#[test]
fn unprovisioned_and_committed_are_classified_but_never_aborted() {
    for committed in [false, true] {
        let mut m = Mock::default();
        if committed {
            let _ = run(MODES[0], TRIALS[2], &mut m);
        }
        for mode in [MODES[1], MODES[2]] {
            let start = m.calls.len();
            let (s, _) = run(mode, TRIALS[2], &mut m);
            assert_eq!(s.transmit_calls, 5);
            assert!(m.calls[start..].iter().all(|b| b[1] != 0x23));
            assert_eq!(
                s.outcome,
                if mode == MODES[1] {
                    InterruptionOutcome::Classified(if committed {
                        RawCardState::CommittedGolden
                    } else {
                        RawCardState::Unprovisioned
                    })
                } else {
                    InterruptionOutcome::Reject(InterruptionError::RecoveryNotStaging)
                }
            );
        }
    }
}

#[test]
fn every_info_byte_is_authenticated_against_the_complete_fixed_response() {
    for branch in [
        "info-unprovisioned",
        "info-staging-incomplete",
        "info-staging-complete",
        "info-committed",
    ] {
        let original = decode(row(branch, 4).response_hex);
        for at in 0..original.len() {
            let mut changed = original.clone();
            changed[at] ^= 0x80;
            let mut m = Mock {
                inject: Some((4, Injection::Bytes(changed.clone()))),
                ..Mock::default()
            };
            let (s, text) = run(MODES[2], TRIALS[1], &mut m);
            assert!(matches!(s.outcome, InterruptionOutcome::Reject(_)));
            assert_eq!(s.transmit_calls, 5);
            assert!(text.contains(&format!("apdu.4.rx_hex={}\n", hex(&changed))));
            assert!(text.contains("apdu.4.comparison="));
            assert!(!m.calls.iter().any(|b| b[1] == 0x23));
        }
    }
}

#[test]
fn named_rejections_stop_at_each_prefix_exchange_and_retain_raw_bytes() {
    for trial in TRIALS {
        let count = if trial == TRIALS[1] {
            5
        } else if trial == TRIALS[0] {
            8
        } else {
            9
        };
        for at in 0..count {
            for injection in [
                Injection::Bytes(vec![0x69, 0x85]),
                Injection::Failure(InterruptionError::Native(pcsc::Error::NotTransacted)),
                Injection::Panic,
                Injection::Excess,
            ] {
                let mut m = Mock {
                    inject: Some((at, injection)),
                    ..Mock::default()
                };
                let (s, text) = run(MODES[0], trial, &mut m);
                assert!(matches!(s.outcome, InterruptionOutcome::Reject(_)));
                assert_eq!(s.transmit_calls, at + 1);
                assert_eq!(m.operations.last(), Some(&"leave"));
                assert!(text.contains(&format!("apdu.{at}.comparison=")));
                assert_eq!(m.timeout, None);
            }
        }
    }
}

#[test]
fn lifecycle_rejection_does_not_claim_retirement_and_retirement_is_fatal() {
    for (bytes, error) in [
        (vec![0x6f, 7], InterruptionError::LifecycleRejected),
        (vec![0x6f, 15], InterruptionError::ResponseRetired),
        (
            vec![0; 219],
            SittingError::SittingResponseLimitExceeded.into(),
        ),
    ] {
        let mut m = Mock {
            inject: Some((8, Injection::Bytes(bytes))),
            ..Mock::default()
        };
        let (s, _) = run(MODES[0], TRIALS[2], &mut m);
        assert_eq!(s.outcome, InterruptionOutcome::Reject(error));
        assert_eq!(m.timeout, None);
    }
}

#[test]
fn removal_transport_exception_is_commit_only_and_still_requires_empty() {
    for error in [pcsc::Error::RemovedCard, pcsc::Error::NoSmartcard] {
        for at in 0..9 {
            let mut m = Mock {
                inject: Some((at, Injection::Failure(InterruptionError::Native(error)))),
                ..Mock::default()
            };
            let (s, _) = run(MODES[0], TRIALS[2], &mut m);
            if at == 8 {
                assert_eq!(s.outcome, InterruptionOutcome::Interrupted);
                assert_eq!(m.timeout, Some(12345));
            } else {
                assert_eq!(
                    s.outcome,
                    InterruptionOutcome::Reject(InterruptionError::Native(error))
                );
                assert_eq!(m.timeout, None);
            }
        }
    }
    for observed in [
        Ok(pcsc::State::PRESENT),
        Ok(pcsc::State::UNKNOWN),
        Ok(pcsc::State::UNAVAILABLE),
        Ok(pcsc::State::EMPTY | pcsc::State::PRESENT),
        Err(InterruptionError::RemovalWaitTimedOut),
    ] {
        let mut m = Mock {
            wait: observed,
            ..Mock::default()
        };
        let (s, text) = run(MODES[0], TRIALS[2], &mut m);
        assert!(matches!(s.outcome, InterruptionOutcome::Reject(_)));
        assert_eq!(m.operations.iter().filter(|v| **v == "wait").count(), 1);
        assert!(text.contains("removal_wait_outcome=Interruption"));
    }
}

#[test]
fn required_wait_is_strict_bounded_and_read_only_for_removal_interrupts() {
    assert_eq!(
        RemovalWaitMs::parse(None),
        Err(InterruptionError::RemovalWaitMissing)
    );
    for value in [
        "",
        "999",
        "600001",
        "-1000",
        "+1000",
        "1000.0",
        " 1000",
        "1000 ",
        "4294967296",
        "10000000000",
    ] {
        assert_eq!(
            RemovalWaitMs::parse(Some(OsStr::new(value))),
            Err(InterruptionError::RemovalWaitInvalid)
        );
    }
    for value in ["1000", "600000"] {
        assert_eq!(
            RemovalWaitMs::parse(Some(OsStr::new(value))).unwrap().get(),
            value.parse().unwrap()
        );
    }
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        RemovalWaitMs::parse(Some(OsStr::from_bytes(&[0xff]))),
        Err(InterruptionError::RemovalWaitInvalid)
    );
    for mode in MODES {
        for trial in TRIALS {
            let mut reads = 0;
            let wait = removal_wait_for(mode, trial, || {
                reads += 1;
                Some("1000".into())
            })
            .unwrap();
            assert_eq!(reads, usize::from(mode == MODES[0] && trial.is_removal()));
            assert_eq!(wait.is_some(), reads == 1);
        }
    }
}

#[test]
fn missing_or_invalid_wait_cli_rejects_before_creating_output_or_contact() {
    let output = PathBuf::from("/tmp").join(interruption_output_basename(MODES[0], TRIALS[2], UTC));
    assert!(!output.exists());
    for value in [None, Some("0"), Some("600001"), Some("invalid")] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_qk-card-enrollment"));
        cmd.args([
            "sitting",
            "interrupt-golden",
            "remove-commit-1",
            SITTING_CAMPAIGN_SOURCE_COMMIT,
            UTC,
            "iMac",
            "SCR3310-01",
            "J3R180-03",
            &hex(SITTING_READER_NAME),
            output.to_str().unwrap(),
        ]);
        cmd.env_remove(REMOVAL_WAIT_ENV);
        if let Some(v) = value {
            cmd.env(REMOVAL_WAIT_ENV, v);
        }
        let result = cmd.output().unwrap();
        assert_eq!(result.status.code(), Some(64));
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8(result.stderr)
            .unwrap()
            .starts_with("result=InterruptionRemovalWait"));
        assert!(!output.exists());
    }
}

struct BrokenWriter {
    limit: usize,
    bytes: Vec<u8>,
    panic: bool,
    flush_fails: bool,
}
impl Write for BrokenWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len() + bytes.len() > self.limit {
            if self.panic {
                panic!("writer probe")
            }
            return Err(io::Error::other("writer probe"));
        }
        self.bytes.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush_fails {
            Err(io::Error::other("flush probe"))
        } else {
            Ok(())
        }
    }
}
#[test]
fn transcript_failures_and_unwind_stop_before_next_contact_and_disconnect() {
    for (limit, panic, flush_fails) in [
        (0, false, false),
        (0, true, false),
        (10000, false, true),
        (2600, false, false),
    ] {
        let mut m = Mock::default();
        let mut t = InterruptionTranscript::new(BrokenWriter {
            limit,
            bytes: Vec::new(),
            panic,
            flush_fails,
        });
        let s = run_interruption(&metadata(MODES[0], TRIALS[0]), &mut m, &mut t);
        assert!(matches!(s.outcome, InterruptionOutcome::Reject(_)));
        assert!(!m.connected);
        if limit == 0 || flush_fails {
            assert!(m.operations.is_empty());
        }
    }
}

#[test]
fn disconnect_failure_is_terminal_and_never_replaces_an_earlier_failure() {
    let mut m = Mock {
        disconnect_failure: true,
        ..Mock::default()
    };
    let (s, _) = run(MODES[1], TRIALS[0], &mut m);
    assert_eq!(
        s.outcome,
        InterruptionOutcome::Reject(SittingError::SittingDisconnectFailed.into())
    );
    let mut m = Mock {
        disconnect_failure: true,
        inject: Some((0, Injection::Bytes(vec![0x6f, 7]))),
        ..Mock::default()
    };
    let (s, text) = run(MODES[1], TRIALS[0], &mut m);
    assert_eq!(
        s.outcome,
        InterruptionOutcome::Reject(InterruptionError::LifecycleRejected)
    );
    assert!(text.contains("disconnect=SittingDisconnectFailed"));
}
