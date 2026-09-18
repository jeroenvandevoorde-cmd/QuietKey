//! HOST-only public-fixture qualification driver, never a target launcher.
//!
//! The parent supplies control pipes on stdin/stdout and one already-open
//! synthetic card descriptor on fd 3. No path, device or transport selector is
//! accepted. Linux owns the concrete poll/fcntl descriptor ABI below; other
//! platforms have no adapter and explicitly report unavailability. The stub is
//! a consequence of that boundary, not an alternative signing implementation.
//!
//! Control records are kind:u8, length:u32le, payload. Input length is <= 4096;
//! actual output QKIP frames retain qk-ipc's MAX_FRAME_BYTES bound.
//! Input kinds: 1 QKIP, 2 QKIP with ancillary-present, 3 typed event, 4 empty
//! automatic step. Event tags: 1 confirm, 2 media PSBT, 3 camera BBQr PSBT,
//! 4 hold complete, 5 SD plus nonce[16], 6 BBQr plus part length:u16le,
//! 7 timeout, 8 removal, 9 cancel. Output kinds: 1 actual QKIP frame,
//! 2 immutable display fact, 3 public screen facts, 4 stage:u8 plus attempted
//! SIGN count:u16le, 5 closed error name, 6 empty action boundary. Screen facts
//! are UTF-8 key=value lines; absent artifact and receipt fields are explicit.
//! This private HOST protocol neither carries a production transcript nor
//! accepts real secrets. The parent must supply only registered public fixtures.

#![deny(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match std::panic::catch_unwind(run) {
        Ok(status) => status,
        Err(_) => ExitCode::from(70),
    }
}

fn run() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _ = arguments.next();
    let mode = arguments.next();
    let profile = arguments.next();
    if arguments.next().is_some() || mode.as_deref() != Some(std::ffi::OsStr::new("normal")) {
        return ExitCode::from(64);
    }
    let profile = match profile.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("01") => *b"01",
        Some("02") => *b"02",
        Some("03") => *b"03",
        _ => return ExitCode::from(64),
    };
    #[cfg(target_os = "linux")]
    {
        driver::run(&profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile;
        eprintln!("QualificationLinuxUnavailable");
        ExitCode::from(69)
    }
}

#[cfg(target_os = "linux")]
mod driver {
    use super::linux_descriptor::{Descriptor, MonotonicClock};
    use qk_core::{
        CoreOutbound, KeypadKey, NormalArtifactFactsV2, NormalProcessEventV2, NormalProcessStageV2,
        NormalProfileV2, NormalScreenV2, NormalSdReceiptV2, NormalSec1210DisplayV2,
        NormalSec1210V2, NormalStageV2, Source,
    };
    use std::fmt::Write as _;
    use std::io::{self, BufWriter, Read, Write};
    use std::process::ExitCode;

    const MAX_CONTROL_BYTES: usize = 4096;
    type Owner = NormalSec1210V2<Descriptor, MonotonicClock>;
    type Result<T> = std::result::Result<T, &'static str>;

    struct Input {
        bytes: [u8; MAX_CONTROL_BYTES],
    }

    impl Drop for Input {
        fn drop(&mut self) {
            self.bytes.fill(0);
        }
    }

    pub(super) fn run(profile: &[u8]) -> ExitCode {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut input = stdin.lock();
        let mut output = BufWriter::new(stdout.lock());
        match drive(profile, &mut input, &mut output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(name) => {
                // Failure while reporting cannot replace the first facade name.
                let _ = packet(&mut output, 5, name.as_bytes());
                let _ = packet(&mut output, 6, &[]);
                let _ = output.flush();
                ExitCode::from(70)
            }
        }
    }

    fn drive(profile: &[u8], input: &mut impl Read, output: &mut impl Write) -> Result<()> {
        let descriptor = Descriptor::inherited().map_err(|_| "QualificationDescriptorRejected")?;
        let (mut owner, opening) = Owner::start(profile, descriptor, MonotonicClock::new())
            .map_err(|error| error.name())?;
        snapshot(&mut owner, Some(opening), output)?;
        let mut scratch = Input {
            bytes: [0; MAX_CONTROL_BYTES],
        };
        loop {
            let (kind, length) = command(input, &mut scratch.bytes)?;
            let payload = scratch
                .bytes
                .get_mut(..length)
                .ok_or("QualificationProtocolRejected")?;
            // Each facade call is synchronous. No control read, display write or
            // callback is serviced while any approved SIGN exchange is pending.
            let result = match kind {
                1 | 2 => owner.receive_qkip(payload, kind == 2),
                3 => owner.handle_event(event(payload)?),
                4 if payload.is_empty() => owner.advance_automatic(),
                _ => return Err("QualificationProtocolRejected"),
            };
            payload.fill(0);
            match result {
                Ok(outbound) => snapshot(&mut owner, outbound, output)?,
                Err(error) => {
                    let _ = display_and_status(&mut owner, output);
                    return Err(error.name());
                }
            }
            if owner.stage() == NormalProcessStageV2::Normal(NormalStageV2::CompletedWiped) {
                return Ok(());
            }
        }
    }

    fn command(input: &mut impl Read, buffer: &mut [u8; MAX_CONTROL_BYTES]) -> Result<(u8, usize)> {
        let mut header = [0; 5];
        input
            .read_exact(&mut header)
            .map_err(|_| "QualificationControlReadFailed")?;
        let [kind, a, b, c, d] = header;
        let length = usize::try_from(u32::from_le_bytes([a, b, c, d]))
            .map_err(|_| "QualificationProtocolRejected")?;
        let payload = buffer
            .get_mut(..length)
            .ok_or("QualificationProtocolRejected")?;
        input
            .read_exact(payload)
            .map_err(|_| "QualificationControlReadFailed")?;
        Ok((kind, length))
    }

    fn event(payload: &[u8]) -> Result<NormalProcessEventV2> {
        Ok(match payload {
            [1] => NormalProcessEventV2::LogicalKey(KeypadKey::EqualsConfirmEnter),
            [2] => NormalProcessEventV2::SelectPsbtSource(Source::MediaPsbt),
            [3] => NormalProcessEventV2::SelectPsbtSource(Source::CameraBbqrPsbt),
            [4] => NormalProcessEventV2::HoldCompleted,
            [5, nonce @ ..] if nonce.len() == 16 => NormalProcessEventV2::SelectSd {
                caller_nonce: nonce
                    .try_into()
                    .map_err(|_| "QualificationProtocolRejected")?,
            },
            [6, lo, hi] => NormalProcessEventV2::SelectBbqr {
                non_final_part_len: u16::from_le_bytes([*lo, *hi]),
            },
            [7] => NormalProcessEventV2::SessionTimeout,
            [8] => NormalProcessEventV2::CardRemoved,
            [9] => NormalProcessEventV2::LogicalKey(KeypadKey::CancelBack),
            _ => return Err("QualificationProtocolRejected"),
        })
    }

    fn snapshot(
        owner: &mut Owner,
        outbound: Option<CoreOutbound>,
        output: &mut impl Write,
    ) -> Result<()> {
        if let Some(outbound) = outbound {
            packet(output, 1, outbound.frame_bytes())?;
        }
        display(owner, output)?;
        if let Some(screen) = owner.screen() {
            packet(output, 3, screen_facts(screen)?.as_bytes())?;
        }
        status(owner, output)?;
        packet(output, 6, &[])?;
        output
            .flush()
            .map_err(|_| "QualificationControlWriteFailed")
    }

    fn display_and_status(owner: &mut Owner, output: &mut impl Write) -> Result<()> {
        display(owner, output)?;
        status(owner, output)
    }

    fn display(owner: &mut Owner, output: &mut impl Write) -> Result<()> {
        while let Some(fact) = owner.take_display_fact() {
            match fact {
                NormalSec1210DisplayV2::Stage(stage) => {
                    packet(output, 2, format!("stage={stage:?}").as_bytes())?;
                }
                NormalSec1210DisplayV2::CardOutcomeUnknown => {
                    let message = fact.message().ok_or("QualificationDisplayRejected")?;
                    packet(output, 2, message.as_bytes())?;
                }
            }
        }
        Ok(())
    }

    fn status(owner: &Owner, output: &mut impl Write) -> Result<()> {
        let count =
            u16::try_from(owner.sign_attempts()).map_err(|_| "QualificationCountRejected")?;
        let [lo, hi] = count.to_le_bytes();
        packet(output, 4, &[stage_wire(owner.stage()), lo, hi])
    }

    fn packet(output: &mut impl Write, kind: u8, bytes: &[u8]) -> Result<()> {
        if bytes.len() > qk_ipc::MAX_FRAME_BYTES {
            return Err("QualificationOutputRejected");
        }
        let length = u32::try_from(bytes.len()).map_err(|_| "QualificationOutputRejected")?;
        let [a, b, c, d] = length.to_le_bytes();
        output
            .write_all(&[kind, a, b, c, d])
            .map_err(|_| "QualificationControlWriteFailed")?;
        output
            .write_all(bytes)
            .map_err(|_| "QualificationControlWriteFailed")
    }

    fn stage_wire(stage: NormalProcessStageV2) -> u8 {
        match stage {
            NormalProcessStageV2::AwaitingProfile => 0xfc,
            NormalProcessStageV2::AwaitingNormalFactor => 0xfd,
            NormalProcessStageV2::Terminated => 0xfe,
            NormalProcessStageV2::Normal(stage) => match stage {
                NormalStageV2::NormalStart => 1,
                NormalStageV2::ProfileBinding => 2,
                NormalStageV2::Transport => 3,
                NormalStageV2::PsbtIntake => 4,
                NormalStageV2::FactorB => 5,
                NormalStageV2::A1Intake => 6,
                NormalStageV2::FactorA1 => 7,
                NormalStageV2::Validation => 8,
                NormalStageV2::Review => 9,
                NormalStageV2::FinalApproval => 10,
                NormalStageV2::ApprovalHeld => 11,
                NormalStageV2::Revalidation => 12,
                NormalStageV2::TerminalASigning => 13,
                NormalStageV2::CardBSigning => 14,
                NormalStageV2::Finalization => 15,
                NormalStageV2::AwaitingExportAction => 16,
                NormalStageV2::TransactionResult => 17,
                NormalStageV2::CompletedWiped => 18,
            },
        }
    }

    fn profile_ascii(profile: NormalProfileV2) -> &'static str {
        match profile {
            NormalProfileV2::SimpleRecovery => "01",
            NormalProfileV2::Inheritance => "02",
            NormalProfileV2::QuantumShelter => "03",
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    fn artifact(text: &mut String, name: &str, facts: Option<NormalArtifactFactsV2>) {
        match facts {
            Some(facts) => {
                let _ = writeln!(text, "{name}=PRESENT");
                let _ = writeln!(text, "{name}.serialized_len={}", facts.serialized_len());
                let _ = writeln!(text, "{name}.sha256={}", hex(&facts.sha256()));
            }
            None => {
                let _ = writeln!(text, "{name}=ABSENT");
            }
        }
    }

    fn receipt(text: &mut String, name: &str, facts: Option<NormalSdReceiptV2>) {
        match facts {
            Some(facts) => {
                let _ = writeln!(text, "{name}=PRESENT");
                let _ = writeln!(text, "{name}.total_len={}", facts.total_len());
            }
            None => {
                let _ = writeln!(text, "{name}=ABSENT");
            }
        }
    }

    fn screen_facts(screen: NormalScreenV2<'_>) -> Result<String> {
        let mut text = String::new();
        match screen {
            NormalScreenV2::Stage(stage) => {
                let _ = writeln!(text, "screen=Stage\nstage={stage:?}");
            }
            NormalScreenV2::ProfileBinding { profile } => {
                let _ = writeln!(
                    text,
                    "screen=ProfileBinding\nprofile={}",
                    profile_ascii(profile)
                );
            }
            NormalScreenV2::ReviewOverview(view) => {
                let _ = writeln!(text, "screen=ReviewOverview\nprofile={}\nnetwork={:?}\nwallet_id={}\ninput_count={}\ntotal_input_amount={}",
                    profile_ascii(view.profile()), view.network(), hex(&view.wallet_id()), view.input_count(), view.total_input_amount());
            }
            NormalScreenV2::ReviewArithmetic(view) => {
                let _ = writeln!(text, "screen=ReviewArithmetic\ntotal_input_amount={}\ntotal_output_amount={}\nfee={}",
                    view.total_input_amount(), view.total_output_amount(), view.fee());
            }
            NormalScreenV2::ReviewRecipient(view) => {
                let _ = writeln!(
                    text,
                    "screen=ReviewRecipient\nindex={}\namount={}\nscript_pubkey={}",
                    view.index(),
                    view.amount(),
                    hex(view.script_pubkey())
                );
            }
            NormalScreenV2::ReviewChange(view) => {
                let _ = writeln!(
                    text,
                    "screen=ReviewChange\nindex={}\namount={}\nscript_pubkey={}\nchild_index={}",
                    view.index(),
                    view.amount(),
                    hex(view.script_pubkey()),
                    view.child_index()
                );
            }
            NormalScreenV2::ReviewOpReturn(view) => {
                let _ = writeln!(
                    text,
                    "screen=ReviewOpReturn\nindex={}\namount={}\nscript_pubkey={}\npayload={}",
                    view.index(),
                    view.amount(),
                    hex(view.script_pubkey()),
                    hex(view.payload())
                );
            }
            NormalScreenV2::ReviewLocktime(view) => {
                let _ = writeln!(text, "screen=ReviewLocktime\nlocktime={}", view.locktime());
            }
            NormalScreenV2::ReviewSequence(view) => {
                let _ = writeln!(
                    text,
                    "screen=ReviewSequence\ninput_index={}\nsequence={}\ndirect_rbf={:?}",
                    view.input_index(),
                    view.sequence(),
                    view.direct_rbf()
                );
            }
            NormalScreenV2::ReviewFeePolicy(view) => {
                let _ = writeln!(
                    text,
                    "screen=ReviewFeePolicy\nidentifier_hex={}",
                    hex(view.identifier())
                );
            }
            NormalScreenV2::ReviewFeeFacts(view) => {
                let _ = writeln!(
                    text,
                    "screen=ReviewFeeFacts\nfee={}\nestimated_vsize={}\nfee_rate_msat_per_vbyte={}",
                    view.fee(),
                    view.estimated_vsize(),
                    view.fee_rate_msat_per_vbyte()
                );
            }
            NormalScreenV2::ReviewWarning(view) => {
                let _ = writeln!(text, "screen=ReviewWarning\nwarning={:?}", view.warning());
            }
            NormalScreenV2::FinalApproval(view) => {
                let _ = writeln!(
                    text,
                    "screen=FinalApproval\nprofile={}\nreview_hash={}",
                    profile_ascii(view.profile()),
                    hex(&view.review_hash())
                );
            }
            NormalScreenV2::TransactionResult(view) => {
                let result = view.result();
                let _ = writeln!(
                    text,
                    "screen=TransactionResult\nprofile={}\nroute={:?}\ntxid={}\nwtxid={}",
                    profile_ascii(result.profile()),
                    result.route(),
                    hex(&result.txid()),
                    hex(&result.wtxid())
                );
                artifact(&mut text, "finalized_psbt", result.finalized_psbt());
                artifact(&mut text, "raw_transaction", result.raw_transaction());
                receipt(
                    &mut text,
                    "finalized_psbt_sd_receipt",
                    result.finalized_psbt_sd_receipt(),
                );
                receipt(
                    &mut text,
                    "raw_transaction_sd_receipt",
                    result.raw_transaction_sd_receipt(),
                );
            }
        }
        if text.len() > MAX_CONTROL_BYTES {
            return Err("QualificationOutputRejected");
        }
        Ok(text)
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux_descriptor {
    use qk_core::{
        Sec1210ClockErrorV2, Sec1210DescriptorErrorV2, Sec1210DescriptorReadV2,
        Sec1210DescriptorV2, Sec1210DescriptorWriteV2, Sec1210MonotonicClockV2,
    };
    use std::fs::File;
    use std::io::{ErrorKind, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::Instant;

    const CARD_FD: i32 = 3;
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const O_ACCMODE: i32 = 3;
    const O_RDWR: i32 = 2;
    const O_NONBLOCK: i32 = 0x800;
    const POLLIN: i16 = 1;
    const POLLOUT: i16 = 4;
    const POLLERR: i16 = 8;
    const POLLHUP: i16 = 16;
    const POLLNVAL: i16 = 32;

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
        fn poll(descriptors: *mut PollFd, count: usize, timeout: i32) -> i32;
    }

    pub(super) struct Descriptor(File);

    impl Descriptor {
        pub(super) fn inherited() -> Result<Self, Sec1210DescriptorErrorV2> {
            // SAFETY: fcntl does not own fd 3, and these Linux commands have the
            // stated integer arguments. Validation precedes sole ownership.
            let flags = unsafe { fcntl(CARD_FD, F_GETFL) };
            if flags < 0 || flags & O_ACCMODE != O_RDWR {
                return Err(Sec1210DescriptorErrorV2);
            }
            // SAFETY: the parent passed one owned, open fd 3 across exec; no
            // other File in this process owns it. This owner closes it once.
            let file = unsafe { File::from_raw_fd(CARD_FD) };
            // SAFETY: F_SETFL takes an integer flag word for the validated fd.
            if unsafe { fcntl(file.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) } < 0 {
                return Err(Sec1210DescriptorErrorV2);
            }
            Ok(Self(file))
        }

        fn ready(
            &self,
            events: i16,
            maximum_wait_ms: u64,
        ) -> Result<Option<bool>, Sec1210DescriptorErrorV2> {
            let timeout = i32::try_from(maximum_wait_ms).map_err(|_| Sec1210DescriptorErrorV2)?;
            let mut descriptor = PollFd {
                fd: self.0.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: poll receives one live repr(C) Linux pollfd, with no
            // retained pointer. The count is one and timeout is bounded.
            let result = unsafe { poll(&mut descriptor, 1, timeout) };
            if result < 0 || descriptor.revents & POLLNVAL != 0 {
                return Err(Sec1210DescriptorErrorV2);
            }
            if result == 0 {
                return Ok(None);
            }
            let ready = descriptor.revents & (events | POLLHUP) != 0;
            if descriptor.revents & POLLERR != 0 && !ready {
                return Err(Sec1210DescriptorErrorV2);
            }
            Ok(ready.then_some(descriptor.revents & POLLHUP != 0))
        }
    }

    impl Sec1210DescriptorV2 for Descriptor {
        fn write(
            &mut self,
            bytes: &[u8],
            maximum_wait_ms: u64,
        ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2> {
            if self.ready(POLLOUT, maximum_wait_ms)?.is_none() {
                return Ok(Sec1210DescriptorWriteV2::TimedOut);
            }
            // Preserve a partial write exactly. The transport rejects it; the
            // adapter must never complete it with an implicit retry.
            match self.0.write(bytes) {
                Ok(length) => Ok(Sec1210DescriptorWriteV2::Bytes(length)),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    Ok(Sec1210DescriptorWriteV2::TimedOut)
                }
                Err(_) => Err(Sec1210DescriptorErrorV2),
            }
        }

        fn read(
            &mut self,
            bytes: &mut [u8],
            maximum_wait_ms: u64,
        ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2> {
            let Some(hangup) = self.ready(POLLIN, maximum_wait_ms)? else {
                return Ok(Sec1210DescriptorReadV2::TimedOut);
            };
            match self.0.read(bytes) {
                Ok(0) => Ok(Sec1210DescriptorReadV2::EndOfStream),
                Ok(length) => Ok(Sec1210DescriptorReadV2::Bytes(length)),
                Err(error) if hangup && error.raw_os_error() == Some(5) => {
                    Ok(Sec1210DescriptorReadV2::EndOfStream)
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    Ok(Sec1210DescriptorReadV2::TimedOut)
                }
                Err(_) => Err(Sec1210DescriptorErrorV2),
            }
        }
    }

    pub(super) struct MonotonicClock(Instant);
    impl MonotonicClock {
        pub(super) fn new() -> Self {
            Self(Instant::now())
        }
    }
    impl Sec1210MonotonicClockV2 for MonotonicClock {
        fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2> {
            u64::try_from(self.0.elapsed().as_millis()).map_err(|_| Sec1210ClockErrorV2)
        }
    }
}
