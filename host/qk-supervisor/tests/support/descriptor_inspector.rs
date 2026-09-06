// Standalone test replacement; the integration test prefixes ROLE,
// EVIDENCE_ROOT and RUNTIME constants before compiling this source.
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
}

struct DescriptorSnapshot {
    fd: i32,
    flags: Result<i32, io::Error>,
    access: Option<Result<i32, io::Error>>,
}

struct Snapshot {
    descriptors: Vec<DescriptorSnapshot>,
    null: Result<Metadata, io::Error>,
    null_descriptors: Vec<(i32, Result<Metadata, io::Error>)>,
}

impl Snapshot {
    fn capture(null_fds: &[i32]) -> Self {
        let descriptors = (0..=256)
            .map(|fd| {
                // SAFETY: fcntl reads this process's descriptor properties.
                let raw_flags = unsafe { fcntl(fd, 1) };
                let flags = if raw_flags < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(raw_flags)
                };
                let access = flags.as_ref().ok().map(|_| {
                    // SAFETY: F_GETFL reads flags and does not alter the fd.
                    let raw_access = unsafe { fcntl(fd, 3) };
                    if raw_access < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(raw_access & 3)
                    }
                });
                DescriptorSnapshot { fd, flags, access }
            })
            .collect();
        // These stat operations open no evidence descriptors. In particular,
        // the inherited fd 2 identity is captured before test redirection.
        let null = std::fs::metadata("/dev/null");
        let null_descriptors = null_fds
            .iter()
            .map(|fd| (*fd, std::fs::metadata(format!("/dev/fd/{fd}"))))
            .collect();
        Self {
            descriptors,
            null,
            null_descriptors,
        }
    }
}

struct Evidence {
    file: File,
}

impl Evidence {
    fn line(&mut self, value: &str) -> bool {
        match self
            .file
            .write_all(value.as_bytes())
            .and_then(|()| self.file.flush())
        {
            Ok(()) => true,
            Err(error) => {
                diagnostic(&format!("evidence_write\tFAIL\t{error:?}\n"));
                false
            }
        }
    }

    fn start(&mut self, name: &str) -> bool {
        self.line(&format!("start\t{name}\n"))
    }

    fn check(&mut self, name: &str, pass: bool, detail: impl std::fmt::Display) -> bool {
        let recorded = self.line(&format!(
            "check\t{name}\t{}\t{detail}\n",
            if pass { "PASS" } else { "FAIL" }
        ));
        pass && recorded
    }

    fn finish(&mut self, pass: bool) -> bool {
        self.line(if pass {
            "result\tPASS\n"
        } else {
            "result\tFAIL\n"
        })
    }
}

fn diagnostic(value: &str) {
    // A broken evidence filesystem can also break stderr. This final best
    // effort has no alternate destination; the parent registers missing files.
    let _ = io::stderr().write_all(value.as_bytes());
    let _ = io::stderr().flush();
}

fn expected() -> (&'static [(i32, i32)], &'static [i32]) {
    match ROLE {
        "decoy" => (&[(0, 2), (1, 2), (2, 1), (3, 0), (4, 1)], &[0, 1, 2, 3, 4]),
        "core" => (
            &[(0, 2), (1, 2), (2, 1), (3, 1), (4, 0), (5, 0), (6, 1)],
            &[2],
        ),
        "io" => (
            &[(0, 2), (1, 2), (2, 1), (3, 0), (4, 0), (5, 1), (6, 1)],
            &[2],
        ),
        _ => (&[], &[]),
    }
}

fn snapshot_checks(snapshot: &Snapshot, evidence: &mut Evidence) -> bool {
    let mut ok = evidence.start("descriptor_snapshot");
    let (expected, _) = expected();
    ok &= evidence.check("role", matches!(ROLE, "decoy" | "core" | "io"), ROLE);
    for descriptor in &snapshot.descriptors {
        let wanted = expected.iter().find(|(fd, _)| *fd == descriptor.fd);
        let name = format!("fd_{}_presence", descriptor.fd);
        let present_ok = match (&descriptor.flags, wanted) {
            (Ok(_), Some(_)) => true,
            (Err(error), None) => error.raw_os_error() == Some(9),
            _ => false,
        };
        ok &= evidence.check(
            &name,
            present_ok,
            format!(
                "expected_open={};observed={:?};access={:?}",
                wanted.is_some(),
                descriptor.flags,
                descriptor.access
            ),
        );
        if let Some((_, wanted_access)) = wanted {
            let access_ok = matches!(&descriptor.access, Some(Ok(value)) if value == wanted_access);
            ok &= evidence.check(
                &format!("fd_{}_access", descriptor.fd),
                access_ok,
                format!("expected={wanted_access};observed={:?}", descriptor.access),
            );
        }
    }
    ok &= evidence.check(
        "null_device_stat",
        snapshot.null.is_ok(),
        metadata_detail(&snapshot.null),
    );
    for (fd, actual) in &snapshot.null_descriptors {
        let same = matches!((&snapshot.null, actual), (Ok(null), Ok(actual)) if null.rdev() == actual.rdev());
        ok &= evidence.check(
            &format!("fd_{fd}_null_identity"),
            same,
            metadata_detail(actual),
        );
    }
    ok
}

fn metadata_detail(value: &Result<Metadata, io::Error>) -> String {
    match value {
        Ok(meta) => format!(
            "dev={};ino={};rdev={};mode={:#o}",
            meta.dev(),
            meta.ino(),
            meta.rdev(),
            meta.mode()
        ),
        Err(error) => format!("error={error:?}"),
    }
}

fn inspect_endpoint(evidence: &mut Evidence, snapshot: &Snapshot) -> bool {
    let mut ok = evidence.start("endpoint_fd0_stat");
    let first = std::fs::metadata("/dev/fd/0");
    ok &= evidence.check("endpoint_fd0_stat", first.is_ok(), metadata_detail(&first));
    ok &= evidence.start("endpoint_fd1_stat");
    let second = std::fs::metadata("/dev/fd/1");
    ok &= evidence.check(
        "endpoint_fd1_stat",
        second.is_ok(),
        metadata_detail(&second),
    );
    let same = matches!((&first, &second), (Ok(first), Ok(second)) if first.dev() == second.dev() && first.ino() == second.ino());
    ok &= evidence.check(
        "endpoint_metadata",
        same,
        format!(
            "fd0={};fd1={}",
            metadata_detail(&first),
            metadata_detail(&second)
        ),
    );

    ok &= evidence.start("runtime_directory");
    let runtime = std::fs::metadata(RUNTIME);
    ok &= evidence.check(
        "runtime_directory",
        matches!(&runtime, Ok(meta) if meta.is_dir()),
        metadata_detail(&runtime),
    );
    let socket_path = Path::new(RUNTIME).join("qkip.sock");
    ok &= evidence.start("socket_path_absent");
    let socket_metadata = std::fs::symlink_metadata(&socket_path);
    ok &= evidence.check(
        "socket_path_absent",
        matches!(&socket_metadata, Err(error) if error.kind() == io::ErrorKind::NotFound),
        metadata_detail(&socket_metadata),
    );
    ok &= evidence.start("socket_reconnect_refused");
    match UnixStream::connect(&socket_path) {
        Ok(_) => ok &= evidence.check("socket_reconnect_refused", false, "unexpected_connection"),
        Err(error) => {
            ok &= evidence.check("socket_reconnect_refused", true, format!("error={error:?}"))
        }
    }

    if !snapshot
        .descriptors
        .first()
        .is_some_and(|fd| fd.flags.is_ok())
    {
        evidence.check("endpoint_available", false, "fd0_not_open_at_snapshot");
        return false;
    }
    // SAFETY: fd 0 is an inherited descriptor owned by this replacement
    // process; the socket owner closes it once when the test process exits.
    let mut socket = unsafe { UnixStream::from_raw_fd(0) };
    ok &= evidence.start("endpoint_local_address");
    let local = socket.local_addr();
    ok &= evidence.check(
        "endpoint_local_address",
        local.is_ok(),
        format!("{local:?}"),
    );
    ok &= evidence.start("endpoint_peer_address");
    let peer_address = socket.peer_addr();
    ok &= evidence.check(
        "endpoint_peer_address",
        peer_address.is_ok(),
        format!("{peer_address:?}"),
    );

    let (sent, expected) = if ROLE == "core" {
        (b'C', b'I')
    } else {
        (b'I', b'C')
    };
    ok &= evidence.start("peer_barrier_write");
    let write = socket.write_all(&[sent]);
    ok &= evidence.check(
        "peer_barrier_write",
        write.is_ok(),
        format!("byte={sent:02x};result={write:?}"),
    );
    let mut peer = [0u8; 1];
    ok &= evidence.start("peer_barrier_read");
    let read = socket.read_exact(&mut peer);
    ok &= evidence.check(
        "peer_barrier_read",
        read.is_ok(),
        format!("bytes={peer:02x?};result={read:?}"),
    );
    ok &= evidence.check(
        "peer_barrier_byte",
        read.is_ok() && peer == [expected],
        format!("expected={expected:02x};observed={:02x}", peer[0]),
    );
    ok
}

fn run(snapshot: &Snapshot, evidence: &mut Evidence) -> bool {
    let mut ok = snapshot_checks(snapshot, evidence);
    ok &= evidence.start("injection_read");
    let injection = match std::fs::read_to_string(Path::new(EVIDENCE_ROOT).join("inject")) {
        Ok(value) => {
            ok &= evidence.check("injection_read", true, format!("present={value:?}"));
            value
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            ok &= evidence.check("injection_read", true, "absent");
            String::new()
        }
        Err(error) => {
            evidence.check("injection_read", false, format!("error={error:?}"));
            return false;
        }
    };
    if injection == format!("{ROLE}:forced-failure") {
        evidence.check("injected_failure", false, "requested");
        return false;
    }
    if ROLE == "core" && injection == "core:panic" {
        panic!("qk163 injected inspector panic");
    }
    if !injection.is_empty()
        && !matches!(
            injection.as_str(),
            "core:panic" | "core:forced-failure" | "io:forced-failure"
        )
    {
        evidence.check("injection_value", false, format!("unknown={injection:?}"));
        return false;
    }
    if ROLE != "decoy" {
        ok &= inspect_endpoint(evidence, snapshot);
    }
    ok
}

fn main() {
    let (_, null_fds) = expected();
    let snapshot = Snapshot::capture(null_fds);
    let root = PathBuf::from(EVIDENCE_ROOT);
    let stderr_path = root.join(format!("{ROLE}.stderr"));
    let stderr = match OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stderr_path)
    {
        Ok(file) => file,
        Err(error) => {
            diagnostic(&format!("stderr_open\tFAIL\t{error:?}\n"));
            std::process::exit(70);
        }
    };
    // SAFETY: redirect only this test replacement's stderr after preserving
    // its inherited properties; this does not alter any product executable.
    if unsafe { dup2(stderr.as_raw_fd(), 2) } < 0 {
        let error = io::Error::last_os_error();
        diagnostic(&format!("stderr_redirect\tFAIL\t{error:?}\n"));
        std::process::exit(70);
    }
    if stderr.as_raw_fd() == 2 {
        // A malformed inherited table may have left fd 2 vacant, allowing
        // open to return it. Keep that redirection live for its error record.
        std::mem::forget(stderr);
    } else {
        drop(stderr);
    }
    let evidence_path = root.join(format!("{ROLE}.evidence"));
    let file = match OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&evidence_path)
    {
        Ok(file) => file,
        Err(error) => {
            diagnostic(&format!("evidence_open\tFAIL\t{error:?}\n"));
            std::process::exit(70);
        }
    };
    let mut evidence = Evidence { file };
    if !evidence.line(&format!("START\trole={ROLE}\n"))
        || !evidence.check(
            "stderr_redirect",
            true,
            "captured_after_descriptor_snapshot",
        )
    {
        std::process::exit(70);
    }
    std::panic::set_hook(Box::new(move |info| {
        diagnostic(&format!("unexpected_panic\tFAIL\t{info}\n"));
        match OpenOptions::new().append(true).open(&evidence_path) {
            Ok(file) => {
                let mut hook_evidence = Evidence { file };
                hook_evidence.check("unexpected_panic", false, info);
            }
            Err(error) => diagnostic(&format!("panic_evidence_open\tFAIL\t{error:?}\n")),
        }
    }));
    let pass = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(&snapshot, &mut evidence)
    })) {
        Ok(pass) => pass,
        Err(_) => false,
    };
    if !evidence.finish(pass) || !pass {
        std::process::exit(70);
    }
    if ROLE == "decoy" {
        loop {
            std::thread::park();
        }
    }
}
