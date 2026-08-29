//! Consuming HOST-only v2 Kit generation and logical print-export boundary.

use crate::secret::{wipe, Secret};
use crate::{HostProvisioningRunV2, ProvisioningError};
use qk_kit::{QrMetadata, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN, QR_PACKED_BYTES};

const FALLBACK_LINE_SYMBOLS: usize = 57;
const FALLBACK_LINES: usize = 4;
const PAGE_BUFFER_BYTES: usize = FRAME_LEN + FALLBACK_SYMBOLS + QR_PACKED_BYTES;
const COPY_COUNT: u8 = 2;
const PAGE_COUNT: u8 = 4;

const _: () = assert!(FALLBACK_LINE_SYMBOLS * FALLBACK_LINES == FALLBACK_SYMBOLS);
const _: () = assert!(PAGE_BUFFER_BYTES == 899);

/// Fixed setup-copy position supplied to the logical print boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitCopyV2 {
    One,
    Two,
}

/// Fixed envelope-share position supplied to the logical print boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitShareIndexV2 {
    One,
    Two,
}

/// Closed callback result for one complete logical page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitPageDispositionV2 {
    Accepted,
    Rejected,
}

/// Immutable scoped view of one complete logical Kit share page.
///
/// The fallback and QR borrows expire with the callback. This type owns no
/// share-equivalent bytes and deliberately implements no clone, copy,
/// formatter, comparison, serializer, or logger trait.
pub struct KitPrintPageV2<'page> {
    copy: KitCopyV2,
    share_index: KitShareIndexV2,
    wallet_id: &'page [u8; 32],
    qr_metadata: QrMetadata,
    fallback: &'page [u8; FALLBACK_SYMBOLS],
    qr_packed: &'page [u8; QR_PACKED_BYTES],
}

impl<'page> KitPrintPageV2<'page> {
    pub const fn copy(&self) -> KitCopyV2 {
        self.copy
    }

    pub const fn share_index(&self) -> KitShareIndexV2 {
        self.share_index
    }

    pub const fn wallet_id(&self) -> &[u8; 32] {
        self.wallet_id
    }

    pub const fn qr_metadata(&self) -> QrMetadata {
        self.qr_metadata
    }

    pub fn fallback_line(&self, line: usize) -> Option<&[u8; FALLBACK_LINE_SYMBOLS]> {
        if line >= FALLBACK_LINES {
            return None;
        }
        let start = line * FALLBACK_LINE_SYMBOLS;
        self.fallback[start..start + FALLBACK_LINE_SYMBOLS]
            .try_into()
            .ok()
    }

    pub const fn qr_packed(&self) -> &[u8; QR_PACKED_BYTES] {
        self.qr_packed
    }
}

/// Non-secret proof that all four fixed logical page callbacks accepted.
///
/// Construction is private. The receipt contains only public wallet identity
/// and fixed completion counts; it owns no frame, fallback, QR, share, pad, or
/// payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitSetupReceiptV2 {
    wallet_id: [u8; 32],
}

impl KitSetupReceiptV2 {
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn copy_count(&self) -> u8 {
        COPY_COUNT
    }

    pub const fn page_count(&self) -> u8 {
        PAGE_COUNT
    }
}

struct PageBuffers {
    frame: [u8; FRAME_LEN],
    fallback: [u8; FALLBACK_SYMBOLS],
    qr: [u8; QR_PACKED_BYTES],
}

impl PageBuffers {
    const fn zeroed() -> Self {
        Self {
            frame: [0u8; FRAME_LEN],
            fallback: [0u8; FALLBACK_SYMBOLS],
            qr: [0u8; QR_PACKED_BYTES],
        }
    }

    fn wipe_all(&mut self) {
        wipe(&mut self.frame);
        wipe(&mut self.fallback);
        wipe(&mut self.qr);
        #[cfg(any(test, feature = "fuzzing"))]
        {
            assert!(self.frame.iter().all(|&byte| byte == 0));
            assert!(self.fallback.iter().all(|&byte| byte == 0));
            assert!(self.qr.iter().all(|&byte| byte == 0));
            #[cfg(test)]
            record_page_buffer_wipe();
        }
    }

    fn prepare(
        &mut self,
        share_index: ShareIndex,
        wallet_id: &[u8; 32],
        share: &[u8; 96],
    ) -> Result<QrMetadata, ProvisioningError> {
        self.wipe_all();
        self.frame = qk_kit::encode_frame(share_index, wallet_id, share);
        qk_kit::encode_fallback(&self.frame, &mut self.fallback)
            .map_err(|_| ProvisioningError::KitEncodingInvariant)?;
        qk_kit::encode_qr(&self.frame, &mut self.qr)
            .map_err(|_| ProvisioningError::KitEncodingInvariant)
    }
}

impl Drop for PageBuffers {
    fn drop(&mut self) {
        self.wipe_all();
    }
}

impl HostProvisioningRunV2 {
    /// Consume one setup run and emit exactly two complete logical Kit copies.
    ///
    /// The callback sequence is fixed as copy one/index one, copy one/index
    /// two, copy two/index one, copy two/index two. Every callback receives a
    /// complete immutable scoped page. Rejection stops the sequence and no
    /// completion receipt is released. The run and all caller-owned codec
    /// output buffers are wiped on every exit path.
    pub fn emit_two_kit_copies<F>(self, mut sink: F) -> Result<KitSetupReceiptV2, ProvisioningError>
    where
        F: for<'page> FnMut(KitPrintPageV2<'page>) -> KitPageDispositionV2,
    {
        let mut buffers = PageBuffers::zeroed();
        if self.nonce.is_none() {
            return Err(ProvisioningError::A1NotReady);
        }

        let mut share_two_scratch = [0u8; 96];
        for (output, (&payload, &pad)) in share_two_scratch.iter_mut().zip(
            self.payload
                .as_bytes()
                .iter()
                .zip(self.kit_r_pad.as_bytes()),
        ) {
            *output = payload ^ pad;
        }
        let share_two = Secret::take(&mut share_two_scratch);
        let wallet_id = self.wallet.wallet_id;

        let pages = [
            (KitCopyV2::One, KitShareIndexV2::One),
            (KitCopyV2::One, KitShareIndexV2::Two),
            (KitCopyV2::Two, KitShareIndexV2::One),
            (KitCopyV2::Two, KitShareIndexV2::Two),
        ];
        for (copy, share_index) in pages {
            let (codec_index, share) = match share_index {
                KitShareIndexV2::One => (ShareIndex::One, self.kit_r_pad.as_bytes()),
                KitShareIndexV2::Two => (ShareIndex::Two, share_two.as_bytes()),
            };
            let qr_metadata = buffers.prepare(codec_index, &wallet_id, share)?;
            let disposition = sink(KitPrintPageV2 {
                copy,
                share_index,
                wallet_id: &wallet_id,
                qr_metadata,
                fallback: &buffers.fallback,
                qr_packed: &buffers.qr,
            });
            buffers.wipe_all();
            if disposition == KitPageDispositionV2::Rejected {
                return Err(ProvisioningError::PrintRejected);
            }
        }

        Ok(KitSetupReceiptV2 { wallet_id })
    }
}

#[cfg(test)]
use core::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static PAGE_BUFFER_WIPES: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn record_page_buffer_wipe() {
    PAGE_BUFFER_WIPES.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn run() -> HostProvisioningRunV2 {
        let transcripts = [[b'1'; 100], [b'2'; 100], [b'3'; 100], [b'4'; 100]];
        HostProvisioningRunV2::from_manual_dice([
            &transcripts[0],
            &transcripts[1],
            &transcripts[2],
            &transcripts[3],
        ])
        .expect("fixed valid transcripts")
    }

    fn reset_wipes() {
        PAGE_BUFFER_WIPES.with(|count| count.set(0));
    }

    fn wipes() -> usize {
        PAGE_BUFFER_WIPES.with(Cell::get)
    }

    #[test]
    fn page_buffer_guard_routes_exactly_899_bytes_through_wipe() {
        crate::secret::reset_wiped_bytes();
        let mut buffers = PageBuffers {
            frame: [0x11; FRAME_LEN],
            fallback: [0x22; FALLBACK_SYMBOLS],
            qr: [0x33; QR_PACKED_BYTES],
        };
        buffers.wipe_all();
        assert_eq!(crate::secret::wiped_bytes(), PAGE_BUFFER_BYTES);
        assert!(buffers.frame.iter().all(|&byte| byte == 0));
        assert!(buffers.fallback.iter().all(|&byte| byte == 0));
        assert!(buffers.qr.iter().all(|&byte| byte == 0));
        drop(buffers);
    }

    #[test]
    fn full_operation_wipes_buffers_on_success_rejection_and_missing_a1() {
        reset_wipes();
        let mut complete = run();
        complete.encrypt_a1(&[0x42; 12]).expect("A1");
        let receipt = complete
            .emit_two_kit_copies(|_| KitPageDispositionV2::Accepted)
            .expect("four pages");
        assert_eq!(receipt.page_count(), 4);
        assert_eq!(wipes(), 9, "prepare+callback per page plus drop");

        for reject_at in 0..4 {
            reset_wipes();
            let mut rejected = run();
            rejected.encrypt_a1(&[0x42; 12]).expect("A1");
            let mut calls = 0usize;
            assert_eq!(
                rejected.emit_two_kit_copies(|_| {
                    let current = calls;
                    calls += 1;
                    if current == reject_at {
                        KitPageDispositionV2::Rejected
                    } else {
                        KitPageDispositionV2::Accepted
                    }
                }),
                Err(ProvisioningError::PrintRejected)
            );
            assert_eq!(calls, reject_at + 1);
            assert_eq!(wipes(), (reject_at + 1) * 2 + 1);
        }

        reset_wipes();
        assert_eq!(
            run().emit_two_kit_copies(|_| panic!("callback must not run")),
            Err(ProvisioningError::A1NotReady)
        );
        assert_eq!(wipes(), 1, "drop-only wipe for unopened page buffers");
    }

    #[test]
    fn callback_unwind_still_drops_and_wipes_the_live_page_buffers() {
        for panic_at in 0..4 {
            reset_wipes();
            let mut run = run();
            run.encrypt_a1(&[0x42; 12]).expect("A1");
            let mut calls = 0usize;
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _ = run.emit_two_kit_copies(|_| {
                    let current = calls;
                    calls += 1;
                    if current == panic_at {
                        panic!("test-only sink unwind");
                    }
                    KitPageDispositionV2::Accepted
                });
            }));
            assert!(result.is_err());
            assert_eq!(calls, panic_at + 1);
            assert_eq!(wipes(), (panic_at + 1) * 2);
        }
    }
}
