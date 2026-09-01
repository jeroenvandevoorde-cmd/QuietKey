//! Opaque, consuming HOST-only Kit-Restore operations.
//!
//! This module never releases recovered payload bytes. It rebinds the two
//! account authorities to exact caller-authenticated D, then consumes the
//! payload into one replacement-B mock boundary or one A1 print/scan-back
//! boundary. Real card I/O and physical printing remain outside this crate.

use crate::secret::{wipe, Secret};
use crate::sha256::Sha256;
use crate::RecoveredKitPayload;
use core::fmt;
use qk_wallet_v2::{rebind_wallet_v2, WalletPublicV2, WalletV2Error};

const PAYLOAD_BYTES: usize = 96;
const SEED_A_OFFSET: usize = 0;
const SIGNER_B_OFFSET: usize = 32;
const A2_OFFSET: usize = 64;
const CAPSULE_BYTES: usize = 67;

const _: () = assert!(A2_OFFSET + 32 == PAYLOAD_BYTES);

/// Closed rejection surface for one consuming HOST Kit-Restore operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreErrorV2 {
    RecoveredWalletMismatch,
    SurvivingA1Mismatch,
    SurvivingBFactorMismatch,
    A1PrintRejected,
    A1VerificationMismatch,
    ReplacementBRejected,
}

impl KitRestoreErrorV2 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::SurvivingA1Mismatch => "SurvivingA1Mismatch",
            Self::SurvivingBFactorMismatch => "SurvivingBFactorMismatch",
            Self::A1PrintRejected => "A1PrintRejected",
            Self::A1VerificationMismatch => "A1VerificationMismatch",
            Self::ReplacementBRejected => "ReplacementBRejected",
        }
    }
}

impl fmt::Display for KitRestoreErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitRestoreErrorV2 {}

/// Closed result from a logical replacement-card mock boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreDispositionV2 {
    Accepted,
    Rejected,
}

/// Closed result from a logical A1 print and scan-back mock boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum A1ReprintDispositionV2 {
    Accepted,
    Rejected,
}

/// Authenticated surviving-B facts supplied by the future card boundary.
///
/// The constructor takes ownership of the caller's A2 buffer and clears it.
/// This owner has no clone, copy, debug, display, equality, serialization, or
/// A2 accessor. The public wallet facts are non-secret and role ordered.
pub struct SurvivingBFactorV2 {
    wallet_id: [u8; 32],
    account_xpub: [u8; 111],
    origin_fingerprint: [u8; 4],
    a2: Secret<32>,
}

impl SurvivingBFactorV2 {
    #[must_use]
    pub fn take(
        wallet_id: [u8; 32],
        account_xpub: [u8; 111],
        origin_fingerprint: [u8; 4],
        a2: &mut [u8; 32],
    ) -> Self {
        Self {
            wallet_id,
            account_xpub,
            origin_fingerprint,
            a2: Secret::take(a2),
        }
    }

    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn account_xpub(&self) -> [u8; 111] {
        self.account_xpub
    }

    #[must_use]
    pub const fn origin_fingerprint(&self) -> [u8; 4] {
        self.origin_fingerprint
    }
}

/// One exact, rebound recovered wallet owner.
///
/// Construction consumes the unbound payload. No payload or secret accessor
/// exists; the only operations consume this owner completely.
pub struct BoundKitRestoreV2 {
    payload: RecoveredKitPayload,
    wallet: WalletPublicV2,
}

impl RecoveredKitPayload {
    /// Rebind recovered A/B authority to exact authenticated descriptor bytes.
    pub fn bind_restore_v2(
        self,
        expected_descriptors: &[[u8; 306]; 2],
        expected_wallet_id: &[u8; 32],
    ) -> Result<BoundKitRestoreV2, KitRestoreErrorV2> {
        let seed_a = payload_part(self._bytes.as_bytes(), SEED_A_OFFSET);
        let signer_b = payload_part(self._bytes.as_bytes(), SIGNER_B_OFFSET);
        let wallet = rebind_wallet_v2(seed_a, signer_b, expected_descriptors, expected_wallet_id)
            .map_err(map_wallet_error)?;
        Ok(BoundKitRestoreV2 {
            payload: self,
            wallet,
        })
    }
}

impl BoundKitRestoreV2 {
    #[must_use]
    pub fn wallet_id(&self) -> [u8; 32] {
        self.wallet.wallet_id()
    }

    #[must_use]
    pub fn account_xpubs(&self) -> [[u8; 111]; 2] {
        self.wallet.account_xpubs()
    }

    #[must_use]
    pub fn origin_fingerprints(&self) -> [[u8; 4]; 2] {
        self.wallet.origin_fingerprints()
    }

    /// Authenticate the surviving A1 before the assertion screen is exposed.
    ///
    /// The caller capsule is cleared by the higher-level session that owns
    /// that hostile boundary. No mock sink is reachable from this step.
    pub fn prepare_replacement_b(
        self,
        surviving_a1: &[u8; CAPSULE_BYTES],
    ) -> Result<PreparedReplacementBV2, KitRestoreErrorV2> {
        self.verify_surviving_a1(surviving_a1)?;
        Ok(PreparedReplacementBV2 { bound: self })
    }

    /// Authenticate the surviving B facts and construct the candidate A1
    /// before the assertion screen is exposed. No print sink is reachable
    /// from this step.
    pub fn prepare_a1_reprint(
        self,
        surviving_b: SurvivingBFactorV2,
        nonce: &[u8; 12],
    ) -> Result<PreparedA1ReprintV2, KitRestoreErrorV2> {
        self.verify_surviving_b(&surviving_b)?;
        let seed_a = payload_part(self.payload._bytes.as_bytes(), SEED_A_OFFSET);
        let a2 = payload_part(self.payload._bytes.as_bytes(), A2_OFFSET);
        let wallet_id = self.wallet.wallet_id();

        let mut candidate = qk_a1::encrypt(a2, &wallet_id, nonce, seed_a);
        let candidate = Secret::take(&mut candidate);
        Ok(PreparedA1ReprintV2 {
            bound: self,
            candidate,
            nonce: *nonce,
        })
    }

    fn verify_surviving_a1(
        &self,
        surviving_a1: &[u8; CAPSULE_BYTES],
    ) -> Result<(), KitRestoreErrorV2> {
        let seed_a = payload_part(self.payload._bytes.as_bytes(), SEED_A_OFFSET);
        let a2 = payload_part(self.payload._bytes.as_bytes(), A2_OFFSET);
        let mut recovered = [0u8; 32];
        let accepted = qk_a1::decrypt(a2, &self.wallet.wallet_id(), surviving_a1, &mut recovered)
            .is_ok()
            && constant_time_eq(seed_a, &recovered);
        wipe(&mut recovered);
        accepted
            .then_some(())
            .ok_or(KitRestoreErrorV2::SurvivingA1Mismatch)
    }

    fn verify_surviving_b(&self, surviving: &SurvivingBFactorV2) -> Result<(), KitRestoreErrorV2> {
        let account_xpubs = self.wallet.account_xpubs();
        let fingerprints = self.wallet.origin_fingerprints();
        let a2 = payload_part(self.payload._bytes.as_bytes(), A2_OFFSET);
        if surviving.wallet_id != self.wallet.wallet_id()
            || surviving.account_xpub != account_xpubs[1]
            || surviving.origin_fingerprint != fingerprints[1]
            || !constant_time_eq(surviving.a2.as_bytes(), a2)
        {
            return Err(KitRestoreErrorV2::SurvivingBFactorMismatch);
        }
        Ok(())
    }
}

/// Prepared replacement-B operation whose branch inputs already authenticated.
///
/// This owner exposes no payload or secret facts and has no clone, copy,
/// formatter, serializer, or signing operation.
pub struct PreparedReplacementBV2 {
    bound: BoundKitRestoreV2,
}

impl PreparedReplacementBV2 {
    /// Consume the prepared owner through exactly one mock replacement sink.
    pub fn complete<F>(self, sink: F) -> Result<ReplacementBReceiptV2, KitRestoreErrorV2>
    where
        F: for<'view> FnOnce(ReplacementBViewV2<'view>) -> KitRestoreDispositionV2,
    {
        let account_xpubs = self.bound.wallet.account_xpubs();
        let fingerprints = self.bound.wallet.origin_fingerprints();
        let wallet_id = self.bound.wallet.wallet_id();
        let view = ReplacementBViewV2 {
            wallet_id: &wallet_id,
            account_xpub: &account_xpubs[1],
            origin_fingerprint: &fingerprints[1],
        };
        if sink(view) != KitRestoreDispositionV2::Accepted {
            return Err(KitRestoreErrorV2::ReplacementBRejected);
        }
        Ok(ReplacementBReceiptV2 {
            wallet_id,
            account_xpub: account_xpubs[1],
            origin_fingerprint: fingerprints[1],
        })
    }
}

/// Prepared A1-reprint operation whose factor and nonce inputs are fixed.
///
/// The candidate remains in a wiping fixed-size owner until the human
/// assertion either authorizes the scoped sink or terminates the session.
pub struct PreparedA1ReprintV2 {
    bound: BoundKitRestoreV2,
    candidate: Secret<CAPSULE_BYTES>,
    nonce: [u8; 12],
}

impl PreparedA1ReprintV2 {
    /// Convert this one-use candidate into the staged process adapter.
    ///
    /// The staged owner permits the caller to copy a borrowed capsule into an
    /// asynchronous print transport, then later consumes one scan-back buffer.
    /// The original synchronous callback API remains unchanged.
    #[cfg(feature = "process-v3")]
    #[must_use]
    pub fn into_staged(self) -> StagedA1ReprintV2 {
        StagedA1ReprintV2 { prepared: self }
    }

    /// Consume the prepared owner through one print and scan-back boundary.
    pub fn complete<F>(self, sink: F) -> Result<A1ReprintReceiptV2, KitRestoreErrorV2>
    where
        F: for<'view> FnOnce(
            A1ReprintViewV2<'view>,
            &'view mut [u8; CAPSULE_BYTES],
        ) -> A1ReprintDispositionV2,
    {
        let mut scan_back = Secret::<CAPSULE_BYTES>::zeroed();
        let disposition = sink(
            A1ReprintViewV2 {
                capsule: self.candidate.as_bytes(),
            },
            scan_back.as_mut_bytes(),
        );
        if disposition != A1ReprintDispositionV2::Accepted {
            return Err(KitRestoreErrorV2::A1PrintRejected);
        }
        if !constant_time_eq(self.candidate.as_bytes(), scan_back.as_bytes()) {
            return Err(KitRestoreErrorV2::A1VerificationMismatch);
        }

        let seed_a = payload_part(self.bound.payload._bytes.as_bytes(), SEED_A_OFFSET);
        let a2 = payload_part(self.bound.payload._bytes.as_bytes(), A2_OFFSET);
        let wallet_id = self.bound.wallet.wallet_id();
        let mut recovered = [0u8; 32];
        if qk_a1::decrypt(a2, &wallet_id, scan_back.as_bytes(), &mut recovered).is_err()
            || !constant_time_eq(seed_a, &recovered)
        {
            wipe(&mut recovered);
            return Err(KitRestoreErrorV2::A1VerificationMismatch);
        }
        wipe(&mut recovered);
        let capsule_sha256 = sha256(self.candidate.as_bytes());
        Ok(A1ReprintReceiptV2 {
            wallet_id,
            nonce: self.nonce,
            capsule_sha256,
        })
    }
}

/// One-use A1 candidate retained across asynchronous print and scan-back.
///
/// The candidate and recovered payload remain inside their existing wiping
/// owners. The only view is a borrow for constructing the print artifact; the
/// only completion consumes this owner and takes then clears the caller's
/// exact scan-back buffer before authenticating it.
#[cfg(feature = "process-v3")]
pub struct StagedA1ReprintV2 {
    prepared: PreparedA1ReprintV2,
}

#[cfg(feature = "process-v3")]
impl StagedA1ReprintV2 {
    /// Borrow the generated capsule for one typed print-artifact constructor.
    #[must_use]
    pub fn capsule(&self) -> &[u8; CAPSULE_BYTES] {
        self.prepared.candidate.as_bytes()
    }

    /// Consume one exact scan-back and authenticate it against the candidate.
    ///
    /// The caller array is zeroed immediately by ownership transfer. Rejection
    /// and success both clear the retained candidate, payload, and scan-back.
    pub fn complete_scan_back(
        self,
        scan_back: &mut [u8; CAPSULE_BYTES],
    ) -> Result<A1ReprintReceiptV2, KitRestoreErrorV2> {
        let scan_back = Secret::take(scan_back);
        if !constant_time_eq(self.prepared.candidate.as_bytes(), scan_back.as_bytes()) {
            return Err(KitRestoreErrorV2::A1VerificationMismatch);
        }

        let seed_a = payload_part(self.prepared.bound.payload._bytes.as_bytes(), SEED_A_OFFSET);
        let a2 = payload_part(self.prepared.bound.payload._bytes.as_bytes(), A2_OFFSET);
        let wallet_id = self.prepared.bound.wallet.wallet_id();
        let mut recovered = [0u8; 32];
        if qk_a1::decrypt(a2, &wallet_id, scan_back.as_bytes(), &mut recovered).is_err()
            || !constant_time_eq(seed_a, &recovered)
        {
            wipe(&mut recovered);
            return Err(KitRestoreErrorV2::A1VerificationMismatch);
        }
        wipe(&mut recovered);
        let capsule_sha256 = sha256(self.prepared.candidate.as_bytes());
        Ok(A1ReprintReceiptV2 {
            wallet_id,
            nonce: self.prepared.nonce,
            capsule_sha256,
        })
    }
}

/// Scoped public facts for one mock replacement-B call.
pub struct ReplacementBViewV2<'view> {
    wallet_id: &'view [u8; 32],
    account_xpub: &'view [u8; 111],
    origin_fingerprint: &'view [u8; 4],
}

impl ReplacementBViewV2<'_> {
    #[must_use]
    pub const fn wallet_id(&self) -> &[u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn account_xpub(&self) -> &[u8; 111] {
        self.account_xpub
    }

    #[must_use]
    pub const fn origin_fingerprint(&self) -> &[u8; 4] {
        self.origin_fingerprint
    }
}

/// Non-authoritative HOST receipt from one accepted replacement-B mock call.
pub struct ReplacementBReceiptV2 {
    wallet_id: [u8; 32],
    account_xpub: [u8; 111],
    origin_fingerprint: [u8; 4],
}

impl ReplacementBReceiptV2 {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn account_xpub(&self) -> [u8; 111] {
        self.account_xpub
    }

    #[must_use]
    pub const fn origin_fingerprint(&self) -> [u8; 4] {
        self.origin_fingerprint
    }
}

/// Immutable scoped view of one generated A1 capsule.
pub struct A1ReprintViewV2<'view> {
    capsule: &'view [u8; CAPSULE_BYTES],
}

impl A1ReprintViewV2<'_> {
    #[must_use]
    pub const fn capsule(&self) -> &[u8; CAPSULE_BYTES] {
        self.capsule
    }
}

/// Non-secret receipt from one verified A1 print/scan-back boundary.
pub struct A1ReprintReceiptV2 {
    wallet_id: [u8; 32],
    nonce: [u8; 12],
    capsule_sha256: [u8; 32],
}

impl A1ReprintReceiptV2 {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn nonce(&self) -> [u8; 12] {
        self.nonce
    }

    #[must_use]
    pub const fn capsule_sha256(&self) -> [u8; 32] {
        self.capsule_sha256
    }
}

fn payload_part(payload: &[u8; PAYLOAD_BYTES], offset: usize) -> &[u8; 32] {
    payload[offset..offset + 32]
        .try_into()
        .expect("const-checked payload partition")
}

fn map_wallet_error(_error: WalletV2Error) -> KitRestoreErrorV2 {
    KitRestoreErrorV2::RecoveredWalletMismatch
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (&left_byte, &right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    let mut hash = Sha256::new();
    hash.update(bytes);
    hash.finish(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::{
        A1ReprintDispositionV2, BoundKitRestoreV2, KitRestoreDispositionV2, SurvivingBFactorV2,
    };
    use crate::secret::{reset_wiped_bytes, wiped_bytes};
    use crate::{combine_frames, RecoveredKitPayload};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const PROVISIONING: &[u8] =
        include_bytes!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
    const KIT_SHARES: &[u8] = include_bytes!("../tests/fixtures/kit_share_v2.txt");
    const FRESH_NONCE: [u8; 12] = *b"QKV2S10NEW01";

    fn fixture_text(bytes: &[u8]) -> &str {
        core::str::from_utf8(bytes).expect("registered ASCII fixture")
    }

    fn field<'a>(fixture: &'a [u8], name: &str) -> &'a str {
        fixture_text(fixture)
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
            .expect("registered field")
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let nibble = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("registered lowercase hex"),
            };
            *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        output
    }

    fn recovered() -> RecoveredKitPayload {
        combine_frames(
            &hex_array::<142>(field(KIT_SHARES, "frame_1_hex")),
            &hex_array::<142>(field(KIT_SHARES, "frame_2_hex")),
        )
        .expect("registered pair")
    }

    fn descriptors() -> [[u8; 306]; 2] {
        [
            field(PROVISIONING, "receive_descriptor")
                .as_bytes()
                .try_into()
                .expect("receive descriptor width"),
            field(PROVISIONING, "change_descriptor")
                .as_bytes()
                .try_into()
                .expect("change descriptor width"),
        ]
    }

    fn wallet_id() -> [u8; 32] {
        hex_array(field(PROVISIONING, "wallet_id"))
    }

    fn bound() -> BoundKitRestoreV2 {
        recovered()
            .bind_restore_v2(&descriptors(), &wallet_id())
            .expect("registered wallet")
    }

    fn surviving_b() -> SurvivingBFactorV2 {
        let mut a2 = hex_array(field(PROVISIONING, "a2_transcript_sha256"));
        SurvivingBFactorV2::take(
            wallet_id(),
            field(PROVISIONING, "role_b_account_xpub")
                .as_bytes()
                .try_into()
                .expect("role-B xpub width"),
            hex_array(field(PROVISIONING, "role_b_origin_fingerprint")),
            &mut a2,
        )
    }

    fn capsule() -> [u8; 67] {
        hex_array(field(PROVISIONING, "a1_capsule_hex"))
    }

    #[test]
    fn each_partial_restore_owner_routes_all_secret_fields_through_wipe() {
        let owner = bound();
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), 96);

        let prepared = bound()
            .prepare_replacement_b(&capsule())
            .expect("registered A1");
        reset_wiped_bytes();
        drop(prepared);
        assert_eq!(wiped_bytes(), 96);

        let prepared = bound()
            .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
            .expect("registered surviving B");
        reset_wiped_bytes();
        drop(prepared);
        assert_eq!(wiped_bytes(), 96 + 67);
    }

    #[test]
    fn every_callback_exit_routes_all_owned_restore_bytes_through_wipe() {
        let prepared = bound()
            .prepare_replacement_b(&capsule())
            .expect("registered A1");
        reset_wiped_bytes();
        assert!(prepared
            .complete(|_| KitRestoreDispositionV2::Rejected)
            .is_err());
        assert_eq!(wiped_bytes(), 96);

        let prepared = bound()
            .prepare_replacement_b(&capsule())
            .expect("registered A1");
        reset_wiped_bytes();
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = prepared.complete(|_| panic!("test unwind"));
        }))
        .is_err());
        assert_eq!(wiped_bytes(), 96);

        let prepared = bound()
            .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
            .expect("registered surviving B");
        reset_wiped_bytes();
        assert!(prepared
            .complete(|_, _| A1ReprintDispositionV2::Rejected)
            .is_err());
        assert_eq!(wiped_bytes(), 96 + 67 + 67);

        let prepared = bound()
            .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
            .expect("registered surviving B");
        reset_wiped_bytes();
        assert!(prepared
            .complete(|view, scan_back| {
                scan_back.copy_from_slice(view.capsule());
                scan_back[31] ^= 1;
                A1ReprintDispositionV2::Accepted
            })
            .is_err());
        assert_eq!(wiped_bytes(), 96 + 67 + 67);

        let prepared = bound()
            .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
            .expect("registered surviving B");
        reset_wiped_bytes();
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _ = prepared.complete(|_, _| panic!("test unwind"));
        }))
        .is_err());
        assert_eq!(wiped_bytes(), 96 + 67 + 67);

        let prepared = bound()
            .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
            .expect("registered surviving B");
        reset_wiped_bytes();
        assert!(prepared
            .complete(|view, scan_back| {
                scan_back.copy_from_slice(view.capsule());
                A1ReprintDispositionV2::Accepted
            })
            .is_ok());
        assert_eq!(wiped_bytes(), 96 + 67 + 67 + 32 + 64);
    }
}
