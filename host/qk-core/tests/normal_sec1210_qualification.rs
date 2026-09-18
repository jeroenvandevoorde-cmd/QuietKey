//! Real HOST executables on inherited synthetic channels; no apparatus access.

#![cfg(all(feature = "sec1210-production", feature = "normal-process"))]

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_qk-normal-sec1210-qualification");

fn bounded_output(arguments: &[&str]) -> Output {
    let mut command = Command::new(BINARY);
    command.args(arguments);
    bounded_command(command)
}

fn bounded_command(mut command: Command) -> Output {
    struct Guard(Option<std::process::Child>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("qualification executable");
    let mut guard = Guard(Some(child));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if guard
            .0
            .as_mut()
            .expect("owned child")
            .try_wait()
            .expect("poll child")
            .is_some()
        {
            return guard
                .0
                .take()
                .expect("owned child")
                .wait_with_output()
                .expect("captured output");
        }
        assert!(
            Instant::now() < deadline,
            "qualification invocation watchdog"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

// Declared artifacts only: no parsing, normalization, hashes or outcome policy
// belongs in this comparator. Each producer must qualify its outcome first.
fn compare_artifacts(
    left: &std::path::Path,
    right: &std::path::Path,
    expected: &[&str],
) -> Result<(), &'static str> {
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    if expected.is_empty() || expected.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("ArtifactDeclarationRejected");
    }
    for root in [left, right] {
        let metadata = std::fs::symlink_metadata(root).map_err(|_| "ArtifactDirectoryMissing")?;
        if !metadata.is_dir() {
            return Err("ArtifactDirectoryRejected");
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(root).map_err(|_| "ArtifactInventoryFailed")? {
            let entry = entry.map_err(|_| "ArtifactInventoryFailed")?;
            let metadata =
                std::fs::symlink_metadata(entry.path()).map_err(|_| "ArtifactInventoryFailed")?;
            if !metadata.is_file() || metadata.len() == 0 {
                return Err("ArtifactFileRejected");
            }
            names.push(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "ArtifactNameRejected")?,
            );
        }
        names.sort_unstable();
        if names != expected {
            return Err("ArtifactSetMismatch");
        }
    }
    for name in expected {
        let mut command = Command::new("cmp");
        command.arg("-s").arg(left.join(name)).arg(right.join(name));
        if !bounded_command(command).status.success() {
            return Err("ArtifactBytesMismatch");
        }
    }
    Ok(())
}

#[test]
fn qualification_rejects_missing_unknown_and_extra_arguments() {
    for arguments in [
        &[][..],
        &["other"][..],
        &["normal"][..],
        &["normal", "00"][..],
        &["normal", "04"][..],
        &["normal", "01", "extra"][..],
    ] {
        let output = bounded_output(arguments);
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn qualification_reports_linux_unavailable_without_runtime_claim() {
    for profile in ["01", "02", "03"] {
        let output = bounded_output(&["normal", profile]);
        assert_eq!(output.status.code(), Some(69));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"QualificationLinuxUnavailable\n");
    }
    eprintln!("UNAVAILABLE: Linux PTY runtime qualification was not run on this platform");
}

#[path = "support/normal_signing_fixture.rs"]
pub mod fixture;
#[cfg(target_os = "linux")]
#[path = "support/normal_sec1210_reader.rs"]
pub mod reader;

#[test]
fn comparator_requires_declared_nonempty_files_and_exact_bytes() {
    use std::fs;
    use std::os::unix::fs::{symlink, DirBuilderExt};
    let root = std::env::temp_dir().join(format!("qk-artifact-cmp-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("exclusive comparator test root");
    let left = root.join("left");
    let right = root.join("right");
    fs::create_dir(&left).unwrap();
    fs::create_dir(&right).unwrap();
    let expected = ["facts.txt", "outcome.txt", "transaction.tx"];
    for name in expected {
        fs::write(left.join(name), b"public emitted bytes\n").unwrap();
        fs::write(right.join(name), b"public emitted bytes\n").unwrap();
    }
    assert_eq!(compare_artifacts(&left, &right, &expected), Ok(()));
    assert!(compare_artifacts(&left, &right, &[]).is_err());
    assert!(compare_artifacts(&left, &right, &["facts.txt", "facts.txt"]).is_err());
    assert!(compare_artifacts(&left, &root.join("missing"), &expected).is_err());
    for name in expected {
        fs::remove_file(right.join(name)).unwrap();
        assert!(compare_artifacts(&left, &right, &expected).is_err());
        fs::write(right.join(name), b"").unwrap();
        assert!(compare_artifacts(&left, &right, &expected).is_err());
        fs::write(right.join(name), b"different public emitted bytes\n").unwrap();
        assert_eq!(
            compare_artifacts(&left, &right, &expected),
            Err("ArtifactBytesMismatch")
        );
        fs::write(right.join(name), b"public emitted bytes\n").unwrap();
    }
    fs::write(right.join("extra"), b"extra").unwrap();
    assert_eq!(
        compare_artifacts(&left, &right, &expected),
        Err("ArtifactSetMismatch")
    );
    fs::remove_file(right.join("extra")).unwrap();
    fs::remove_file(right.join("transaction.tx")).unwrap();
    symlink(left.join("transaction.tx"), right.join("transaction.tx")).unwrap();
    assert_eq!(
        compare_artifacts(&left, &right, &expected),
        Err("ArtifactFileRejected")
    );
    fs::remove_file(right.join("transaction.tx")).unwrap();
    fs::write(right.join("transaction.tx"), b"public emitted bytes\n").unwrap();
    fs::remove_file(left.join("outcome.txt")).unwrap();
    fs::remove_file(right.join("outcome.txt")).unwrap();
    assert!(
        compare_artifacts(&left, &right, &expected).is_err(),
        "two missing outcomes are not equivalence"
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
mod linux_pty {
    use super::{fixture, reader, BINARY};
    use fixture::{Fault, SignFault};
    use qk_device_wire::{
        BodyRef, Capability, DisplayBody, MessageKind, NormalStage, OneWayProtocol, ReviewBody,
    };
    use qk_io::{Artifact, BrokerSession, MockInput, MockOutputWriter, Request, Sink, Source};
    use qk_ipc::{MessageKind as IpcKind, ReceivedFrame, StreamDecoder};
    use reader::{ChildGuard, ReaderSnapshot, ReaderTask};
    use std::collections::{BTreeMap, VecDeque};
    use std::fs::{self, DirBuilder, File, OpenOptions};
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(40);
    const CHILD_WAIT: Duration = Duration::from_secs(300);
    const UNKNOWN: &str = "Signing was not completed by this terminal. The card may have produced a signature before the failure.";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug)]
    enum Route {
        Sd,
        Bbqr,
    }

    struct Scenario {
        profile: u8,
        route: Route,
        psbt: Vec<u8>,
        signs: usize,
        fault: Fault,
        rejection: Option<&'static str>,
        apdus: usize,
    }
    impl Scenario {
        fn success(profile: u8, route: Route, psbt: Vec<u8>, signs: usize) -> Self {
            Self {
                profile,
                route,
                psbt,
                signs,
                fault: Fault::None,
                rejection: None,
                apdus: 8 + signs,
            }
        }
        fn expected_artifacts(&self) -> Vec<&'static str> {
            if self.rejection.is_some() {
                return vec!["outcome.txt"];
            }
            let mut names = vec!["facts.txt", "outcome.txt"];
            match (self.profile, self.route) {
                (1 | 2, Route::Sd) => names.extend(["finalized.psbt", "transaction.tx"]),
                (1 | 2, Route::Bbqr) => names.push("finalized.psbt"),
                (3, _) => names.push("transaction.tx"),
                _ => panic!("registered profile"),
            }
            names
        }
        fn broker(&self, evidence: &Evidence, label: &'static str) -> Broker {
            let mut broker = Broker::new(evidence, label);
            broker.psbt = self.psbt.clone();
            let root = evidence.root.join(label);
            DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("new artifact root");
            broker.artifact_root = Some(root);
            broker
        }
    }

    #[derive(Default)]
    struct Facts(BTreeMap<&'static str, String>);
    impl Facts {
        fn insert(&mut self, key: &'static str, value: impl ToString) {
            let value = value.to_string();
            if let Some(previous) = self.0.insert(key, value.clone()) {
                assert_eq!(previous, value, "emitted public fact changed: {key}");
            }
        }
        fn integrated(&mut self, screens: &[String]) {
            for screen in screens {
                let keys: &[&'static str] = match screen.lines().next() {
                    Some("screen=ReviewOverview") => {
                        &["profile", "wallet_id", "input_count", "total_input_amount"]
                    }
                    Some("screen=ReviewArithmetic") => {
                        &["total_input_amount", "total_output_amount", "fee"]
                    }
                    Some("screen=FinalApproval") => &["profile", "review_hash"],
                    Some("screen=TransactionResult") => &["profile", "route", "txid", "wtxid"],
                    _ => continue,
                };
                for &key in keys {
                    let values: Vec<_> = screen
                        .lines()
                        .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='))
                        .collect();
                    assert_eq!(values.len(), 1, "one emitted field: {key}");
                    self.insert(key, values[0]);
                }
            }
        }
        fn reference(&mut self, display: DisplayBody<'_>) {
            match display {
                DisplayBody::Review(ReviewBody::Overview {
                    profile,
                    wallet_id,
                    input_count,
                    total_input,
                    ..
                }) => {
                    self.insert("profile", format!("{:02}", profile.wire_value()));
                    self.insert("wallet_id", hex_text(wallet_id));
                    self.insert("input_count", input_count);
                    self.insert("total_input_amount", total_input);
                }
                DisplayBody::Review(ReviewBody::Arithmetic {
                    total_input,
                    total_output,
                    fee,
                }) => {
                    self.insert("total_input_amount", total_input);
                    self.insert("total_output_amount", total_output);
                    self.insert("fee", fee);
                }
                DisplayBody::Review(ReviewBody::FinalApproval {
                    profile,
                    review_hash,
                }) => {
                    self.insert("profile", format!("{:02}", profile.wire_value()));
                    self.insert("review_hash", hex_text(review_hash));
                }
                DisplayBody::Result(result) => {
                    self.insert("profile", format!("{:02}", result.profile().wire_value()));
                    self.insert("route", format!("{:?}", result.route()));
                    self.insert("txid", hex_text(result.txid()));
                    self.insert("wtxid", hex_text(result.wtxid()));
                }
                _ => {}
            }
        }
        fn write(&self, root: &Path) {
            let expected = [
                "fee",
                "input_count",
                "profile",
                "review_hash",
                "route",
                "total_input_amount",
                "total_output_amount",
                "txid",
                "wallet_id",
                "wtxid",
            ];
            assert_eq!(self.0.keys().copied().collect::<Vec<_>>(), expected);
            let mut file = private_file(&root.join("facts.txt"));
            for (key, value) in &self.0 {
                writeln!(file, "{key}={value}").unwrap();
            }
        }
    }
    fn hex_text(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn record_outcome(broker: &Broker, case: &Scenario, facts: &Facts) {
        let root = broker
            .artifact_root
            .as_ref()
            .expect("declared artifact directory");
        let mut outcome = private_file(&root.join("outcome.txt"));
        if case.rejection.is_some() {
            assert_eq!(
                broker.export_starts, 0,
                "no partial export, including initiation"
            );
            assert!(
                broker.artifacts.is_empty()
                    && broker.pending.is_none()
                    && broker.pending_bytes.is_empty()
            );
            writeln!(outcome, "outcome=terminated\napproval_consumed={}\nsign_attempts={}\ncard_outcome_unknown={}", case.signs != 0, case.signs, case.signs != 0).unwrap();
        } else {
            assert!(broker.pending.is_none() && broker.pending_bytes.is_empty());
            assert_eq!(broker.export_starts, case.expected_artifacts().len() - 2);
            if let Some(psbt) = broker.artifacts.get("finalized.psbt") {
                assert!(psbt.starts_with(b"psbt\xff"));
            }
            if let Some(transaction) = broker.artifacts.get("transaction.tx") {
                assert!(!transaction.is_empty());
            }
            facts.write(root);
            writeln!(outcome, "outcome=completed\napproval_consumed=true\nsign_attempts={}\ncard_outcome_unknown=false", case.signs).unwrap();
        }
    }

    struct Evidence {
        root: PathBuf,
        complete: bool,
    }
    impl Evidence {
        fn new(label: &str) -> Self {
            let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "qk-normal-sec1210-{}-{nonce}-{label}",
                std::process::id()
            ));
            DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("exclusive evidence root");
            assert_eq!(
                fs::metadata(&root)
                    .expect("root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            Self {
                root,
                complete: false,
            }
        }
        fn file(&self, name: &str) -> File {
            private_file(&self.root.join(name))
        }
        fn success(mut self) {
            // Only this exclusively-created test root is removed, after all
            // children and descriptor threads have been reaped and joined.
            fs::remove_dir_all(&self.root).expect("remove owned successful evidence root");
            self.complete = true;
        }
    }
    impl Drop for Evidence {
        fn drop(&mut self) {
            if !self.complete {
                eprintln!("retained qualification evidence: {}", self.root.display());
            }
        }
    }
    fn private_file(path: &Path) -> File {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("fresh private evidence");
        assert_eq!(
            file.metadata().expect("evidence mode").permissions().mode() & 0o777,
            0o600
        );
        file
    }

    fn record_executable(evidence: &Evidence, label: &str, path: &Path, features: &str) {
        let binary = path.canonicalize().expect("exact executable path");
        let mut identity = evidence.file(&format!("{label}-build.txt"));
        writeln!(identity, "binary={}", binary.display()).expect("binary path");
        writeln!(
            identity,
            "bytes={}",
            fs::metadata(&binary).expect("binary metadata").len()
        )
        .expect("binary size");
        writeln!(
            identity,
            "selection=--no-default-features --features {features}"
        )
        .expect("binary selection");
        // Artifact identity is an observation, never a substitute for executing
        // the selected child. Failure to measure it fails this HOST test.
        for (kind, mut command) in [
            ("sha256", {
                let mut command = Command::new("sha256sum");
                command.arg(&binary);
                command
            }),
            ("source", {
                let mut command = Command::new("git");
                command
                    .current_dir(env!("CARGO_MANIFEST_DIR"))
                    .args(["rev-parse", "HEAD"]);
                command
            }),
        ] {
            command
                .stdin(Stdio::null())
                .stdout(evidence.file(&format!("{label}-{kind}.txt")))
                .stderr(evidence.file(&format!("{label}-{kind}.stderr")));
            let mut child = reader::spawn_with_fds(command, &[]).expect("identity observer");
            assert!(child
                .wait_timeout(WAIT)
                .expect("bounded identity observer")
                .success());
        }
    }

    #[derive(Default)]
    struct Action {
        frames: Vec<Vec<u8>>,
        displays: Vec<String>,
        screens: Vec<String>,
        status: Option<(u8, u16)>,
        error: Option<String>,
    }

    struct Integrated {
        child: ChildGuard,
        input: ChildStdin,
        output: ChildStdout,
        reader: Option<ReaderTask>,
        log: File,
        status: Option<(u8, u16)>,
        displays: Vec<String>,
        screens: Vec<String>,
        error: Option<String>,
    }

    impl Integrated {
        fn spawn(evidence: &Evidence, fault: Fault, fragment_size: usize) -> Self {
            Self::spawn_profile(evidence, 1, fault, fragment_size)
        }
        fn spawn_profile(
            evidence: &Evidence,
            profile: u8,
            fault: Fault,
            fragment_size: usize,
        ) -> Self {
            record_executable(
                evidence,
                "integrated",
                Path::new(BINARY),
                "sec1210-production,normal-process",
            );
            let (master, slave) = reader::pty_pair().expect("anonymous raw PTY");
            let mut command = Command::new(BINARY);
            command
                .args(["normal", &format!("{profile:02}")])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(evidence.file("integrated.stderr"));
            let mut child = reader::spawn_with_fds(command, &[(slave.as_raw_fd(), 3)])
                .expect("spawn integrated driver");
            drop(slave);
            let card = ReaderTask::start(
                master,
                profile,
                fault,
                fragment_size,
                &evidence.root.join("integrated-card.frames"),
            )
            .expect("reader thread");
            let input = child.child.stdin.take().expect("control input");
            let output = child.child.stdout.take().expect("control output");
            Self {
                child,
                input,
                output,
                reader: Some(card),
                log: evidence.file("integrated-control.frames"),
                status: None,
                displays: Vec::new(),
                screens: Vec::new(),
                error: None,
            }
        }
        fn read_action(&mut self) -> Action {
            let deadline = Instant::now() + WAIT;
            let mut action = Action::default();
            for _ in 0..128 {
                let mut header = [0; 5];
                reader::read_exact_timeout(
                    &mut self.output,
                    &mut header,
                    deadline.saturating_duration_since(Instant::now()),
                )
                .expect("bounded driver header");
                let [kind, a, b, c, d] = header;
                let length = u32::from_le_bytes([a, b, c, d]) as usize;
                assert!(length <= qk_ipc::MAX_FRAME_BYTES, "bounded driver record");
                let mut body = vec![0; length];
                reader::read_exact_timeout(
                    &mut self.output,
                    &mut body,
                    deadline.saturating_duration_since(Instant::now()),
                )
                .expect("bounded driver body");
                self.log.write_all(&header).expect("record header");
                self.log.write_all(&body).expect("record body");
                match kind {
                    1 => action.frames.push(body),
                    2 => action
                        .displays
                        .push(String::from_utf8(body).expect("display UTF-8")),
                    3 => action
                        .screens
                        .push(String::from_utf8(body).expect("screen UTF-8")),
                    4 => {
                        let [stage, low, high] = body.as_slice() else {
                            panic!("status shape")
                        };
                        action.status = Some((*stage, u16::from_le_bytes([*low, *high])));
                    }
                    5 => {
                        assert!(action.error.is_none(), "one closed error");
                        action.error = Some(String::from_utf8(body).expect("closed error ASCII"));
                    }
                    6 => {
                        assert!(body.is_empty());
                        self.log.flush().expect("flush action evidence");
                        self.status = action.status.or(self.status);
                        self.displays.extend(action.displays.iter().cloned());
                        self.screens.extend(action.screens.iter().cloned());
                        if let Some(error) = &action.error {
                            assert!(self.error.is_none());
                            self.error = Some(error.clone());
                        }
                        return action;
                    }
                    _ => panic!("unknown output kind"),
                }
            }
            panic!("bounded action record count")
        }
        fn send(&mut self, kind: u8, body: &[u8]) -> Action {
            assert!(self.error.is_none(), "no control after terminal outcome");
            assert!(body.len() <= 4096);
            let [a, b, c, d] = u32::try_from(body.len())
                .expect("bounded control")
                .to_le_bytes();
            reader::write_all_timeout(&mut self.input, &[kind, a, b, c, d], WAIT)
                .expect("control header");
            reader::write_all_timeout(&mut self.input, body, WAIT).expect("control payload");
            self.read_action()
        }
        fn settle(&mut self, action: Action, broker: &mut Broker) {
            let mut pending = VecDeque::from(action.frames);
            for _ in 0..4096 {
                if self.error.is_some() {
                    assert!(pending.is_empty(), "no export queued after failure");
                    return;
                }
                let Some(frame) = pending.pop_front() else {
                    return;
                };
                let reply = broker.accept(&fixture::decode_one(&frame));
                for fragment in reply.chunks(1024) {
                    let action = self.send(1, fragment);
                    pending.extend(action.frames);
                    if self.error.is_some() {
                        break;
                    }
                }
            }
            panic!("bounded broker progression")
        }
        fn act(&mut self, kind: u8, body: &[u8], broker: &mut Broker) {
            let action = self.send(kind, body);
            self.settle(action, broker);
        }
        fn approval(&mut self, broker: &mut Broker) {
            let action = self.read_action();
            self.settle(action, broker);
            assert_eq!(self.status, Some((2, 0)));
            self.act(3, &[1], broker);
            self.act(3, &[2], broker);
            assert_eq!(self.status, Some((5, 0)));
            self.act(4, &[], broker);
            assert_eq!(self.status, Some((7, 0)));
            self.act(4, &[], broker);
            for _ in 0..400 {
                if self.status == Some((10, 0)) {
                    break;
                }
                assert!(
                    self.error.is_none(),
                    "preapproval failure: {:?}",
                    self.error
                );
                self.act(3, &[1], broker);
            }
            assert_eq!(self.status, Some((10, 0)));
            assert_eq!(
                self.reader.as_ref().expect("reader").snapshot().signs,
                0,
                "no SIGN before HoldCompleted"
            );
            assert!(broker.artifacts.is_empty());
            assert!(self
                .screens
                .iter()
                .any(|screen| screen.starts_with("screen=FinalApproval\n")));
        }
        fn finish(mut self, expected: i32) -> ReaderSnapshot {
            assert_eq!(
                self.child
                    .wait_timeout(CHILD_WAIT)
                    .expect("child reaped")
                    .code(),
                Some(expected)
            );
            self.reader
                .take()
                .expect("reader owner")
                .finish()
                .expect("reader joined")
        }
    }

    struct Broker {
        session: BrokerSession,
        psbt: Vec<u8>,
        pending: Option<(Sink, Artifact)>,
        artifacts: BTreeMap<&'static str, Vec<u8>>,
        root: PathBuf,
        prefix: &'static str,
        artifact_root: Option<PathBuf>,
        pending_bytes: Vec<u8>,
        pending_len: usize,
        export_starts: usize,
    }
    impl Broker {
        fn new(evidence: &Evidence, prefix: &'static str) -> Self {
            Self {
                session: BrokerSession::new(),
                psbt: fixture::psbt(),
                pending: None,
                artifacts: BTreeMap::new(),
                root: evidence.root.clone(),
                prefix,
                artifact_root: None,
                pending_bytes: Vec::new(),
                pending_len: 0,
                export_starts: 0,
            }
        }
        fn accept(&mut self, frame: &ReceivedFrame) -> Vec<u8> {
            let request = (frame.header().kind() == IpcKind::OperationRequest)
                .then(|| qk_io::parse_request(frame.payload()).expect("actual broker grammar"));
            let mut input = match request {
                Some(Request::IngressBegin {
                    source: Source::MediaPsbt,
                    ..
                }) => Some(
                    MockInput::try_new(Source::MediaPsbt, &fixture::media_record(&self.psbt))
                        .expect("public PSBT"),
                ),
                Some(Request::IngressBegin {
                    source: Source::CameraA1Candidate,
                    ..
                }) => Some(
                    MockInput::try_new(Source::CameraA1Candidate, &fixture::a1())
                        .expect("public A1 fixture"),
                ),
                Some(Request::IngressBegin { .. }) => panic!("unexpected ingress source"),
                _ => None,
            };
            if let Some(Request::EgressBegin {
                sink,
                artifact,
                total_len,
                ..
            }) = request
            {
                assert!(self.pending.replace((sink, artifact)).is_none());
                assert!(self.pending_bytes.is_empty());
                self.pending_len = total_len as usize;
                self.export_starts += 1;
            }
            if let Some(Request::EgressWrite { offset, chunk }) = request {
                assert!(self.pending.is_some());
                assert_eq!(offset as usize, self.pending_bytes.len());
                self.pending_bytes.extend_from_slice(chunk);
                assert!(self.pending_bytes.len() <= self.pending_len);
            }
            let finish = matches!(request, Some(Request::EgressFinish));
            let mut writer = (finish && self.pending.expect("active export").0 != Sink::Bbqr)
                .then(|| MockOutputWriter::new(self.pending.expect("active export").0));
            let reply = self
                .session
                .accept(frame, input.as_mut(), writer.as_mut())
                .expect("broker accepts actual emitted request");
            if let Some(request) = request {
                assert_eq!(
                    reply.status(),
                    qk_io::ReplyStatus::Success(request.operation())
                );
            }
            if finish {
                let (_, artifact) = self.pending.take().expect("finished export");
                let name = match artifact {
                    Artifact::FinalizedPsbt => "finalized.psbt",
                    Artifact::RawTransaction => "transaction.tx",
                    _ => panic!("unrelated export"),
                };
                assert_eq!(self.pending_bytes.len(), self.pending_len);
                let bytes = if let Some(writer) = writer {
                    let emitted = writer.final_bytes().expect("actual completed SD bytes");
                    assert_eq!(emitted, self.pending_bytes);
                    emitted.to_vec()
                } else {
                    // The BBQr broker receives these actual emitted bytes, then
                    // returns its encoded frames for the owner to verify.
                    self.pending_bytes.clone()
                };
                self.pending_bytes.clear();
                let path = match &self.artifact_root {
                    Some(root) => root.join(name),
                    None => self.root.join(format!("{}-{name}", self.prefix)),
                };
                private_file(&path)
                    .write_all(&bytes)
                    .expect("record actual emitted artifact");
                assert!(
                    self.artifacts.insert(name, bytes).is_none(),
                    "one artifact per route"
                );
            }
            reply.frame_bytes().to_vec()
        }
    }

    #[test]
    fn integrated_real_binary_signs_after_approval_and_exports_through_fragmented_pty() {
        let evidence = Evidence::new("integrated-pass");
        let mut broker = Broker::new(&evidence, "integrated");
        let mut driver = Integrated::spawn(&evidence, Fault::None, 1);
        driver.approval(&mut broker);
        driver.act(3, &[4], &mut broker);
        assert_eq!(driver.status, Some((16, 1)));
        assert!(
            broker.artifacts.is_empty(),
            "no export without explicit route"
        );
        let mut select_sd = vec![5];
        select_sd.extend_from_slice(&[0x51; 16]);
        driver.act(3, &select_sd, &mut broker);
        assert_eq!(driver.status, Some((17, 1)));
        assert_eq!(broker.artifacts.len(), 2);
        assert!(broker.artifacts["finalized.psbt"].starts_with(b"psbt\xff"));
        assert!(!broker.artifacts["transaction.tx"].is_empty());
        assert!(driver
            .screens
            .iter()
            .any(|screen| screen.contains("screen=TransactionResult\n")
                && screen.contains("route=Sd\n")
                && screen.contains("finalized_psbt=PRESENT\n")));
        driver.act(3, &[1], &mut broker);
        assert_eq!(driver.status, Some((18, 1)));
        let trace = driver.finish(0);
        assert_eq!(trace.signs, 1);
        assert_eq!(trace.apdus.len(), 9);
        assert_eq!(trace.commands.len(), 14);
        assert!(trace.model_dropped);
        drop(broker);
        evidence.success();
    }

    #[test]
    fn integrated_wrong_card_binding_stops_before_signing_or_export() {
        let evidence = Evidence::new("binding-rejected");
        let mut driver = Integrated::spawn(&evidence, Fault::InfoWallet, 8);
        let action = driver.read_action();
        assert_eq!(action.error.as_deref(), Some("CardWalletBindingMismatch"));
        assert!(action.frames.is_empty());
        assert!(!driver.displays.iter().any(|fact| fact == UNKNOWN));
        let trace = driver.finish(70);
        assert_eq!(trace.signs, 0);
        assert!(trace.model_dropped);
        evidence.success();
    }

    fn terminal_sign_case(label: &str, fault: SignFault, name: &str) {
        let evidence = Evidence::new(label);
        let mut broker = Broker::new(&evidence, "integrated");
        let mut driver = Integrated::spawn(
            &evidence,
            Fault::Sign {
                ordinal: 1,
                kind: fault,
            },
            3,
        );
        driver.approval(&mut broker);
        driver.act(3, &[4], &mut broker);
        assert_eq!(driver.error.as_deref(), Some(name));
        assert_eq!(driver.status, Some((0xfe, 1)));
        assert_eq!(
            driver
                .displays
                .iter()
                .filter(|fact| fact.as_str() == UNKNOWN)
                .count(),
            1
        );
        assert!(
            broker.artifacts.is_empty(),
            "terminal operation exports nothing"
        );
        assert!(!driver
            .screens
            .iter()
            .any(|screen| screen.starts_with("screen=TransactionResult\n")));
        let trace = driver.finish(70);
        assert_eq!(trace.signs, 1);
        assert_eq!(trace.apdus.len(), 9, "nothing sent after terminal SIGN");
        assert!(trace.model_dropped);
        drop(broker);
        evidence.success();
    }

    #[test]
    fn integrated_malformed_signature_is_terminal_and_has_no_export() {
        terminal_sign_case(
            "malformed-signature",
            SignFault::MalformedDer,
            "CardSignatureMalformed",
        );
    }
    #[test]
    fn integrated_removal_is_terminal_and_has_no_export() {
        terminal_sign_case(
            "removed-signature",
            SignFault::Removed,
            "Sec1210DescriptorClosed",
        );
    }
    #[test]
    fn integrated_silent_card_is_bounded_and_has_no_export() {
        terminal_sign_case(
            "silent-signature",
            SignFault::TimedOut,
            "Sec1210DeadlineExceeded",
        );
    }

    struct BrokerTask {
        stop: Arc<AtomicBool>,
        shutdown: UnixStream,
        handle: Option<JoinHandle<Broker>>,
    }
    impl BrokerTask {
        fn start(mut endpoint: UnixStream, mut broker: Broker) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let task_stop = stop.clone();
            let shutdown = endpoint.try_clone().expect("broker shutdown owner");
            let handle = thread::spawn(move || {
                let mut decoder = StreamDecoder::new();
                let deadline = Instant::now() + CHILD_WAIT;
                while !task_stop.load(Ordering::Acquire) {
                    assert!(Instant::now() < deadline, "reference broker watchdog");
                    let mut byte = [0];
                    match reader::read_exact_timeout(
                        &mut endpoint,
                        &mut byte,
                        Duration::from_millis(20),
                    ) {
                        Ok(()) => {}
                        Err("HarnessDeadlineExceeded") => continue,
                        Err("HarnessPeerClosed") if task_stop.load(Ordering::Acquire) => break,
                        Err("HarnessPeerClosed") => break,
                        Err(error) => panic!("reference broker input: {error}"),
                    }
                    let outcome = decoder.ingest(&byte, false).expect("reference QKIP frame");
                    if outcome.frame_ready() {
                        let frame = decoder.take_frame().expect("reference frame owner");
                        let reply = broker.accept(&frame);
                        reader::write_all_timeout(&mut endpoint, &reply, WAIT)
                            .expect("reference broker reply");
                    }
                }
                broker
            });
            Self {
                stop,
                shutdown,
                handle: Some(handle),
            }
        }
        fn finish(mut self) -> Broker {
            self.stop.store(true, Ordering::Release);
            let _ = self.shutdown.shutdown(Shutdown::Both);
            self.handle
                .take()
                .expect("broker task")
                .join()
                .expect("broker joined")
        }
    }
    impl Drop for BrokerTask {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = self.shutdown.shutdown(Shutdown::Both);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn reference_binary(evidence: &Evidence) -> PathBuf {
        if let Some(path) = std::env::var_os("QK_NORMAL_REFERENCE_BINARY") {
            let path = PathBuf::from(path);
            assert!(
                path.is_absolute() && path.is_file(),
                "explicit reference artifact"
            );
            return path;
        }
        let host = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("host workspace");
        let target = evidence.root.join("reference-target");
        let mut command = Command::new("cargo");
        command
            .current_dir(host)
            .args([
                "build",
                "--manifest-path",
                "Cargo.toml",
                "-p",
                "qk-core",
                "--bin",
                "qk-core-host",
                "--locked",
                "--offline",
                "--no-default-features",
                "--features",
                "host-runtime",
            ])
            .env("CARGO_TARGET_DIR", &target)
            .stdin(Stdio::null())
            .stdout(evidence.file("reference-build.stdout"))
            .stderr(evidence.file("reference-build.stderr"));
        let mut child = reader::spawn_with_fds(command, &[]).expect("isolated reference build");
        assert!(child
            .wait_timeout(CHILD_WAIT)
            .expect("bounded reference build")
            .success());
        target.join("debug/qk-core-host")
    }

    fn run_integrated(evidence: &Evidence, case: &Scenario) {
        let mut broker = case.broker(evidence, "integrated");
        let mut driver = Integrated::spawn_profile(evidence, case.profile, case.fault, 8);
        if case.rejection.is_some() && case.signs == 0 {
            let action = driver.read_action();
            assert!(action.frames.is_empty());
        } else {
            driver.approval(&mut broker);
            driver.act(3, &[4], &mut broker);
        }
        if let Some(name) = case.rejection {
            assert_eq!(driver.error.as_deref(), Some(name));
            assert_eq!(
                driver
                    .displays
                    .iter()
                    .filter(|fact| fact.as_str() == UNKNOWN)
                    .count(),
                usize::from(case.signs != 0)
            );
            if case.signs != 0 {
                assert_eq!(driver.status, Some((0xfe, case.signs as u16)));
            }
            assert!(!driver
                .screens
                .iter()
                .any(|screen| screen.starts_with("screen=TransactionResult\n")));
        } else {
            assert!(driver.error.is_none());
            assert_eq!(driver.status, Some((16, case.signs as u16)));
            assert_eq!(broker.export_starts, 0, "no export before route choice");
            let action = match case.route {
                Route::Sd => {
                    let mut bytes = vec![5];
                    bytes.extend_from_slice(&[0x51; 16]);
                    bytes
                }
                Route::Bbqr => {
                    let mut bytes = vec![6];
                    bytes.extend_from_slice(&2680u16.to_le_bytes());
                    bytes
                }
            };
            driver.act(3, &action, &mut broker);
            assert!(driver.error.is_none());
            assert_eq!(driver.status, Some((17, case.signs as u16)));
            driver.act(3, &[1], &mut broker);
            assert_eq!(driver.status, Some((18, case.signs as u16)));
        }
        let mut facts = Facts::default();
        facts.integrated(&driver.screens);
        let trace = driver.finish(if case.rejection.is_some() { 70 } else { 0 });
        assert_eq!(trace.signs, case.signs);
        assert_eq!(trace.apdus.len(), case.apdus);
        // This matrix explicitly uses zero WTX and zero reader extensions.
        assert_eq!(trace.commands.len(), 5 + case.apdus);
        assert!(trace.model_dropped);
        record_outcome(&broker, case, &facts);
    }

    fn paired_case(label: &str, case: Scenario) {
        let evidence = Evidence::new(label);
        // Declare the entire common set before collecting either output.
        let expected = case.expected_artifacts();
        run_integrated(&evidence, &case);
        run_reference(&evidence, &case);
        super::compare_artifacts(
            &evidence.root.join("integrated"),
            &evidence.root.join("reference"),
            &expected,
        )
        .expect("external byte-only comparison of qualified emitted artifacts");
        evidence.success();
    }

    #[test]
    fn differential_all_profiles_routes_and_missing_signature_counts() {
        for profile in 1..=3 {
            for route in [Route::Sd, Route::Bbqr] {
                for (name, psbt, signs) in fixture::differential_psbts() {
                    paired_case(
                        &format!("matrix-{profile}-{route:?}-{name}"),
                        Scenario::success(profile, route, psbt, signs),
                    );
                }
            }
        }
    }

    #[test]
    fn differential_binding_failures_stop_at_their_own_checkpoints_without_export() {
        for (fault, name, apdus) in fixture::binding_cases() {
            paired_case(
                name,
                Scenario {
                    profile: 1,
                    route: Route::Sd,
                    psbt: fixture::psbt(),
                    signs: 0,
                    fault,
                    rejection: Some(name),
                    apdus,
                },
            );
        }
    }

    #[test]
    fn differential_signing_rejections_and_partial_removal_never_export() {
        for (kind, name, ordinal) in fixture::signing_cases() {
            paired_case(
                &format!("rejection-{kind:?}-{ordinal}"),
                Scenario {
                    profile: 1,
                    route: Route::Sd,
                    psbt: fixture::psbt_with_inputs(3),
                    signs: ordinal,
                    fault: Fault::Sign { ordinal, kind },
                    rejection: Some(name),
                    apdus: 8 + ordinal,
                },
            );
        }
        let mut case = Scenario::success(1, Route::Sd, fixture::psbt(), 1);
        case.fault = Fault::Sign {
            ordinal: 1,
            kind: SignFault::HighS,
        };
        paired_case("high-s-normalized", case);
    }

    fn body_label(body: BodyRef<'_>) -> &'static str {
        match body {
            BodyRef::Display(_) => "Display",
            BodyRef::Keypad(_) => "Keypad",
            BodyRef::CardRequest(_) => "CardRequest",
            BodyRef::CardResponse(_) => "CardResponse",
            BodyRef::CardApduRequest(_) => "CardApduRequest",
            BodyRef::CardApduResponse(_) => "CardApduResponse",
            BodyRef::CameraInput(_) => "CameraInput",
            BodyRef::MediaInput(_) => "MediaInput",
            BodyRef::OutputReply(_) => "OutputReply",
            BodyRef::PrintOutput(_) => "PrintOutput",
            BodyRef::MediaOutput(_) => "MediaOutput",
        }
    }

    fn device_frame(
        channel: &mut File,
        decoder: &mut qk_device_wire::StreamDecoder,
    ) -> Result<qk_device_wire::ReceivedFrame, &'static str> {
        let deadline = Instant::now() + WAIT;
        loop {
            let mut byte = [0];
            reader::read_exact_timeout(
                channel,
                &mut byte,
                deadline.saturating_duration_since(Instant::now()),
            )?;
            if decoder
                .ingest(&byte)
                .expect("reference display grammar")
                .frame_ready()
            {
                return Ok(decoder.take_frame().expect("reference display owner"));
            }
        }
    }
    fn keypad(channel: &mut File, protocol: &mut OneWayProtocol, body: &[u8]) {
        let mut frame = vec![0; qk_device_wire::HEADER_BYTES + body.len()];
        let length = protocol
            .next(MessageKind::KeypadEvent)
            .expect("keypad sequence")
            .encode(body, &mut frame)
            .expect("keypad frame");
        assert_eq!(length, frame.len());
        reader::write_all_timeout(channel, &frame, WAIT).expect("reference keypad write");
    }

    #[test]
    fn independent_reference_binary_uses_existing_channels_and_exports_actual_artifacts() {
        let evidence = Evidence::new("reference-pass");
        let case = Scenario::success(1, Route::Sd, fixture::psbt(), 1);
        run_reference(&evidence, &case);
        evidence.success();
    }

    fn run_reference(evidence: &Evidence, case: &Scenario) {
        let binary = reference_binary(evidence);
        record_executable(evidence, "reference", &binary, "host-runtime");
        let (broker_peer, child_qkip) = UnixStream::pair().expect("connected reference endpoint");
        let (mut display, display_child) = reader::pipe_pair().expect("display pipe");
        let (keypad_child, mut keys) = reader::pipe_pair().expect("keypad pipe");
        let (response_child, responses) = reader::pipe_pair().expect("card response pipe");
        let (requests, request_child) = reader::pipe_pair().expect("card request pipe");
        let input: OwnedFd = child_qkip
            .try_clone()
            .expect("reference input duplicate")
            .into();
        let output: OwnedFd = child_qkip.into();
        let mut command = Command::new(binary);
        command
            .args(["normal", &format!("{:02}", case.profile)])
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(evidence.file("reference.stderr"));
        let mut child = reader::spawn_with_fds(
            command,
            &[
                (display_child.as_raw_fd(), 3),
                (keypad_child.as_raw_fd(), 4),
                (response_child.as_raw_fd(), 5),
                (request_child.as_raw_fd(), 6),
            ],
        )
        .expect("spawn separate reference executable");
        drop((display_child, keypad_child, response_child, request_child));
        let card = ReaderTask::start_reference(
            requests,
            responses,
            case.profile,
            case.fault,
            &evidence.root.join("reference-card.frames"),
        )
        .expect("reference card task");
        let broker = BrokerTask::start(broker_peer, case.broker(evidence, "reference"));
        let mut decoder = qk_device_wire::StreamDecoder::new(Capability::Display);
        let mut protocol = OneWayProtocol::new(Capability::Keypad);
        let mut display_log = evidence.file("reference-display.txt");
        let mut completed = false;
        let mut saw_approval = false;
        let mut saw_result = false;
        let mut facts = Facts::default();
        let mut display_count = 0;
        let mut stages = Vec::new();
        for _ in 0..512 {
            let frame = match device_frame(&mut display, &mut decoder) {
                Ok(frame) => frame,
                Err("HarnessPeerClosed") if case.rejection.is_some() => break,
                Err(error) => panic!("reference display: {error}"),
            };
            let body = frame.parsed_body().expect("reference typed display");
            display_count += 1;
            if let BodyRef::Display(DisplayBody::Stage(stage)) = body {
                stages.push(stage);
            }
            match body {
                BodyRef::Display(display) => writeln!(display_log, "{display:?}"),
                other => writeln!(display_log, "{}", body_label(other)),
            }
            .expect("public reference display record");
            if let BodyRef::Display(display) = body {
                facts.reference(display);
            }
            match body {
                BodyRef::Display(DisplayBody::Profile(_)) => {
                    keypad(&mut keys, &mut protocol, &[1, 0x13])
                }
                BodyRef::Display(DisplayBody::Stage(NormalStage::Transport)) => {
                    keypad(&mut keys, &mut protocol, &[2, 4])
                }
                BodyRef::Display(DisplayBody::Review(ReviewBody::FinalApproval { .. })) => {
                    assert_eq!(
                        card.snapshot().signs,
                        0,
                        "reference SIGN also waits for approval"
                    );
                    saw_approval = true;
                    keypad(&mut keys, &mut protocol, &[3]);
                }
                BodyRef::Display(DisplayBody::Review(_)) => {
                    keypad(&mut keys, &mut protocol, &[1, 0x13])
                }
                BodyRef::Display(DisplayBody::Stage(NormalStage::AwaitingExportAction)) => {
                    assert!(saw_approval);
                    assert!(
                        case.rejection.is_none(),
                        "failed scenario must not reach export action"
                    );
                    let mut body = match case.route {
                        Route::Sd => vec![4],
                        Route::Bbqr => vec![5],
                    };
                    match case.route {
                        Route::Sd => body.extend_from_slice(&[0x51; 16]),
                        Route::Bbqr => body.extend_from_slice(&2680u16.to_le_bytes()),
                    }
                    keypad(&mut keys, &mut protocol, &body);
                }
                BodyRef::Display(DisplayBody::Result(_)) => {
                    saw_result = true;
                    keypad(&mut keys, &mut protocol, &[1, 0x13]);
                }
                BodyRef::Display(DisplayBody::Stage(NormalStage::CompletedWiped)) => {
                    completed = true;
                    break;
                }
                BodyRef::Display(DisplayBody::Stage(_)) => {}
                _ => panic!("unexpected reference display"),
            }
        }
        if case.rejection.is_none() {
            assert!(completed && saw_approval && saw_result);
        } else {
            assert!(!completed && !saw_result);
            assert_eq!(
                saw_approval,
                case.signs != 0,
                "exact reference failure checkpoint"
            );
        }
        let expected_stages = [
            NormalStage::NormalStart,
            NormalStage::Transport,
            NormalStage::PsbtIntake,
            NormalStage::FactorB,
            NormalStage::A1Intake,
            NormalStage::FactorA1,
            NormalStage::Validation,
            NormalStage::ApprovalHeld,
            NormalStage::Revalidation,
            NormalStage::TerminalASigning,
            NormalStage::CardBSigning,
            NormalStage::Finalization,
            NormalStage::AwaitingExportAction,
            NormalStage::CompletedWiped,
        ];
        if case.rejection.is_some() && case.signs == 0 {
            assert_eq!(
                display_count, 0,
                "binding failure precedes the first display"
            );
        } else {
            let count = if case.rejection.is_some() { 11 } else { 14 };
            assert_eq!(
                stages,
                expected_stages[..count],
                "exact reference display checkpoint"
            );
        }
        assert_eq!(
            child
                .wait_timeout(CHILD_WAIT)
                .expect("reference child reaped")
                .code(),
            Some(if case.rejection.is_some() { 70 } else { 0 })
        );
        let trace = card.finish().expect("reference card joined");
        let broker = broker.finish();
        assert_eq!(trace.signs, case.signs);
        assert_eq!(
            trace.apdus.len(),
            case.apdus,
            "no writes beyond the expected checkpoint"
        );
        assert!(trace.model_dropped);
        record_outcome(&broker, case, &facts);
        drop((child, broker, keys, display, display_log));
    }
}
