//! HOST-only QuietKey trusted-process shell.
//!
//! This crate owns one QKIP core endpoint, parses the exact qk-io peer grammar,
//! and exposes only typed mock Display, Keypad, and CardSlot capabilities. It
//! orchestrates the ratified v2 provisioning flow and one purpose-bound normal
//! A1+B review, approval, signing, finalization, and export flow through the
//! approved leaf crates and byte-complete HOST card protocol. Transported bytes
//! remain hostile input. No real-device, process-containment, target,
//! production, or Gate claim exists.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod capability;
#[cfg(feature = "normal-process")]
mod card_process_v1;
mod error;
mod io_wire;
#[cfg(feature = "kit-v3")]
mod kit_artifact_v2;
#[cfg(feature = "kit-v3")]
mod kit_intake_v2;
#[cfg(feature = "kit-v3")]
mod kit_restore_v2;
#[cfg(feature = "kit-v3")]
mod kit_spend_v2;
#[cfg(feature = "normal-v3")]
mod normal_artifact_v2;
#[cfg(feature = "normal-process")]
mod normal_process_v2;
#[cfg(feature = "normal-v3")]
mod normal_v2;
#[cfg(feature = "host-runtime")]
mod process;
mod session;
mod session_id;
mod setup_artifact_v2;
mod setup_v2;
mod sha256;
#[allow(unsafe_code)]
mod wipe;

pub use capability::{
    CardBPublicBindingV2, CardInstanceV2, CardMockErrorV2, CardPresence, CoreDeviceGrants,
    CoreScreen, KeypadKey, MockCardSlot, MockDisplay, MockKeypad, NormalCardBDataV2,
    NormalCardBSignatureV2, NormalCardMockErrorV2,
};
#[cfg(feature = "normal-process")]
pub use card_process_v1::{
    bind_normal_card_v1, verify_provisioned_card_v1, CardInfoV1, CardProcessErrorV1,
};
pub use error::{CoreError, Interruption, IoRejection};
pub use io_wire::{Operation, Source};
#[cfg(feature = "kit-v3")]
pub use kit_artifact_v2::{
    KitArtifactErrorV2, KitDeliveryReceiveOutcomeV2, KitDeliverySessionV2, KitExportActionV2,
    KitExportResultV2, KitExportRouteV2, KitRawTransactionFactsV2, KitSdReceiptV2,
};
#[cfg(feature = "kit-v3")]
pub use kit_intake_v2::{
    KitDoorV2, KitFallbackProgressV2, KitForeignInputV2, KitFrameIdentityV2, KitInputModeV2,
    KitIntakeErrorV2, KitIntakeOutcomeV2, KitIntakeReadyV2, KitIntakeScreenV2, KitIntakeSessionV2,
    KitShareOrdinalV2, KIT_FALLBACK_TABLE_V2,
};
#[cfg(feature = "kit-v3")]
pub use kit_restore_v2::{
    AuthorizedA1ReprintV2, CardRemainsStatementV2, HumanAssertionDigitV2, KitRestoreActionV2,
    KitRestoreArtifactV2, KitRestoreErrorV2, KitRestoreForeignOperationV2, KitRestoreOutcomeV2,
    KitRestoreScreenV2, KitRestoreSessionV2, KitRestoreStageV2, MandatoryFreshWalletMigrationV2,
};
#[cfg(feature = "kit-v3")]
pub use kit_spend_v2::{
    CoordinatorCompletenessStatementV2, KitSpendApprovalIdentityV2, KitSpendAssertionDigitV2,
    KitSpendCycleTokenV2, KitSpendErrorV2, KitSpendFinalizedFactsV2, KitSpendForeignOperationV2,
    KitSpendOutcomeV2, KitSpendRecipientFactV2, KitSpendReviewPositionV2, KitSpendScreenV2,
    KitSpendSessionV2, KitSpendStageV2,
};
#[cfg(feature = "normal-v3")]
pub use normal_artifact_v2::{
    NormalArtifactErrorV2, NormalArtifactFactsV2, NormalArtifactKindV2, NormalExportActionV2,
    NormalExportProgressV2, NormalExportRequestV2, NormalExportResultV2, NormalExportRouteV2,
    NormalProfileV2, NormalRouteExposureV2, NormalSdReceiptV2,
};
#[cfg(feature = "normal-process")]
pub use normal_process_v2::{
    NormalProcessControllerV2, NormalProcessErrorV2, NormalProcessEventV2, NormalProcessStageV2,
};
#[cfg(feature = "normal-process")]
pub use normal_v2::NormalCardBSigningRequestV2;
#[cfg(feature = "normal-v3")]
pub use normal_v2::{
    NormalApprovalIdentityV2, NormalApprovalTokenV2, NormalArithmeticViewV2, NormalChangeViewV2,
    NormalErrorV2, NormalFeeFactsViewV2, NormalFeePolicyViewV2, NormalFinalApprovalViewV2,
    NormalLocktimeViewV2, NormalOpReturnViewV2, NormalOverviewViewV2, NormalProgressV2,
    NormalReceiveOutcomeV2, NormalRecipientFactV2, NormalRecipientViewV2, NormalReviewPositionV2,
    NormalScreenV2, NormalSequenceViewV2, NormalSessionV2, NormalStageV2,
    NormalTransactionResultViewV2, NormalWarningViewV2,
};
#[cfg(feature = "host-runtime")]
pub use process::{run_core_host_process, run_normal_core_host_process, CoreHostProcessError};
#[cfg(feature = "kit-v3")]
pub use qk_kit::{KitRestoreDispositionV2, SurvivingBFactorV2};
pub use session::{
    CoreMode, CoreOutbound, CoreReceiveEvent, CoreReceiveOutcome, CoreSession, CoreState,
    HostileIngress,
};
pub use setup_v2::{
    CeremonyPurposeV2, EntropyInputModeV2, SetupErrorV2, SetupOutcomeV2, SetupProgressV2,
    SetupPublicFactsV2, SetupReceiveOutcomeV2, SetupScreenV2, SetupSessionV2, SetupStageV2,
    SpareBChoiceV2, MANUAL_TRANSCRIPT_BYTES_V2,
};

/// Exact QK-DEC-144 inner peer version.
pub const INNER_VERSION: u8 = 1;
/// Exact request/response inner header width.
pub const INNER_HEADER_BYTES: usize = 8;
/// Exact deterministic qk-io transfer chunk ceiling.
pub const MAX_CHUNK_BYTES: usize = 262_144;
/// Exact largest hostile artifact accepted by the HOST shell.
pub const MAX_INGRESS_BYTES: usize = 2_097_152;

const _: () = assert!(MAX_INGRESS_BYTES == qk_ipc::MAX_PAYLOAD_BYTES);

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz {
    pub use crate::io_wire::{
        encode_ingress_begin, encode_ingress_read, parse_response, ExpectedResponse, Response,
    };
    pub use crate::session::fuzz_start_session;
    pub use crate::wipe::{reset_wiped_bytes, wiped_bytes};
}
