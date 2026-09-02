//! HOST-only QuietKey supervisor lifecycle and process-launch reference.
//!
//! This crate owns no wallet, card, key, share, transaction, or other secret
//! material. Its non-default runtime launches three HOST product address spaces
//! with fixed mock descriptors. UID, namespace, seccomp, kernel, physical
//! device, target privilege and production enforcement remain Gate C work.

#![deny(unsafe_code)]

mod lifecycle;
#[cfg(feature = "host-runtime")]
#[allow(unsafe_code)]
mod runtime;

pub use lifecycle::{
    Child, Device, MockGrantSet, ProcessLifecycle, ProcessLifecycleAction, ProcessLifecycleError,
    ProcessLifecycleEvent, ProcessLifecycleOutcome, ProcessLifecycleState, ProcessRole, Supervisor,
    SupervisorAction, SupervisorError, SupervisorEvent, SupervisorOutcome, SupervisorState,
};
#[cfg(feature = "host-runtime")]
pub use qk_ipc::{
    inherited_endpoint, receive_bytes_once, receive_once, UnixReceiveError, UnixReceiveOutcome,
};
#[cfg(feature = "host-runtime")]
pub use runtime::{
    parse_launcher_arguments, run_host_launcher, LauncherInvocation, LauncherInvocationError,
    LauncherMode, LauncherProfile, LauncherRuntimeError,
};
