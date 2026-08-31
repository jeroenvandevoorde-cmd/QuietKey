//! Fixed guarded owners for the two slice-5 print artifacts.

use crate::wipe;
use qk_provisioning::{KitCopyV2, KitPrintPageV2, KitShareIndexV2};

pub(crate) const A1_PRINT_ARTIFACT_BYTES: usize = 67;
pub(crate) const KIT_PRINT_ARTIFACT_BYTES: usize = 829;

const KIT_MAGIC: &[u8; 4] = b"QKKP";
const KIT_VERSION: u8 = 1;
const FALLBACK_LINES: usize = 4;
const FALLBACK_LINE_BYTES: usize = 57;
const QR_PENALTY_COUNT: usize = 8;

const _: () = assert!(
    KIT_MAGIC.len()
        + 1
        + 1
        + 1
        + 32
        + 1
        + QR_PENALTY_COUNT * 4
        + FALLBACK_LINES * FALLBACK_LINE_BYTES
        + 529
        == KIT_PRINT_ARTIFACT_BYTES
);

/// Guarded canonical A1 capsule prepared for its single print transfer.
///
/// This type deliberately implements no clone, copy, formatter, comparison,
/// serializer, or logger trait.
pub(crate) struct A1PrintArtifactV2 {
    bytes: [u8; A1_PRINT_ARTIFACT_BYTES],
}

impl A1PrintArtifactV2 {
    /// Move one mutable capsule copy under this owner and clear the source.
    pub(crate) fn take(source: &mut [u8; A1_PRINT_ARTIFACT_BYTES]) -> Self {
        let bytes = *source;
        wipe::bytes(source);
        Self { bytes }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; A1_PRINT_ARTIFACT_BYTES] {
        &self.bytes
    }

    pub(crate) fn matches(&self, candidate: &[u8]) -> bool {
        self.bytes.as_slice() == candidate
    }
}

impl Drop for A1PrintArtifactV2 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
    }
}

/// Guarded byte-exact QKKP page prepared for its single print transfer.
///
/// This type deliberately implements no clone, copy, formatter, comparison,
/// serializer, or logger trait.
pub(crate) struct KitPrintArtifactV2 {
    bytes: [u8; KIT_PRINT_ARTIFACT_BYTES],
}

impl KitPrintArtifactV2 {
    /// Copy one complete scoped leaf page into the canonical qk-core owner.
    ///
    /// `None` is the closed artifact-invariant outcome for an impossible leaf
    /// mask or incomplete fixed page view. The partially built owner is wiped
    /// by Drop before the rejection returns.
    pub(crate) fn try_from_page(page: KitPrintPageV2<'_>) -> Option<Self> {
        let copy = match page.copy() {
            KitCopyV2::One => 1,
            KitCopyV2::Two => 2,
        };
        let share_index = match page.share_index() {
            KitShareIndexV2::One => 1,
            KitShareIndexV2::Two => 2,
        };
        let metadata = page.qr_metadata();
        if metadata.mask > 7 {
            return None;
        }

        let mut artifact = Self {
            bytes: [0u8; KIT_PRINT_ARTIFACT_BYTES],
        };
        let mut cursor = 0usize;
        append(&mut artifact.bytes, &mut cursor, KIT_MAGIC)?;
        append(&mut artifact.bytes, &mut cursor, &[KIT_VERSION])?;
        append(&mut artifact.bytes, &mut cursor, &[copy])?;
        append(&mut artifact.bytes, &mut cursor, &[share_index])?;
        append(
            &mut artifact.bytes,
            &mut cursor,
            page.wallet_id().as_slice(),
        )?;
        append(&mut artifact.bytes, &mut cursor, &[metadata.mask])?;
        for penalty in metadata.penalties {
            append(&mut artifact.bytes, &mut cursor, &penalty.to_le_bytes())?;
        }
        for line in 0..FALLBACK_LINES {
            append(
                &mut artifact.bytes,
                &mut cursor,
                page.fallback_line(line)?.as_slice(),
            )?;
        }
        append(
            &mut artifact.bytes,
            &mut cursor,
            page.qr_packed().as_slice(),
        )?;
        if cursor != KIT_PRINT_ARTIFACT_BYTES {
            return None;
        }
        Some(artifact)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; KIT_PRINT_ARTIFACT_BYTES] {
        &self.bytes
    }
}

impl Drop for KitPrintArtifactV2 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
    }
}

fn append<const N: usize>(target: &mut [u8; N], cursor: &mut usize, value: &[u8]) -> Option<()> {
    let end = cursor.checked_add(value.len())?;
    target.get_mut(*cursor..end)?.copy_from_slice(value);
    *cursor = end;
    Some(())
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::{
        A1PrintArtifactV2, KitPrintArtifactV2, A1_PRINT_ARTIFACT_BYTES, KIT_PRINT_ARTIFACT_BYTES,
    };
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use qk_provisioning::{
        HostProvisioningRunV2, KitCopyV2, KitPageDispositionV2, KitShareIndexV2,
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn run() -> HostProvisioningRunV2 {
        let transcripts = [[b'1'; 100], [b'2'; 100], [b'3'; 100], [b'4'; 100]];
        HostProvisioningRunV2::from_manual_dice([
            &transcripts[0],
            &transcripts[1],
            &transcripts[2],
            &transcripts[3],
        ])
        .unwrap()
    }

    #[test]
    fn a1_owner_takes_source_matches_exactly_and_wipes_on_drop() {
        let mut source = [0x5a; A1_PRINT_ARTIFACT_BYTES];
        reset_wiped_bytes();
        let owner = A1PrintArtifactV2::take(&mut source);
        assert_eq!(source, [0; A1_PRINT_ARTIFACT_BYTES]);
        assert_eq!(wiped_bytes(), A1_PRINT_ARTIFACT_BYTES);
        assert!(owner.matches(&[0x5a; A1_PRINT_ARTIFACT_BYTES]));
        assert!(!owner.matches(&[0x5b; A1_PRINT_ARTIFACT_BYTES]));
        assert_eq!(owner.as_bytes(), &[0x5a; A1_PRINT_ARTIFACT_BYTES]);

        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), A1_PRINT_ARTIFACT_BYTES);
    }

    #[test]
    fn qkkp_owner_serializes_all_four_pages_in_fixed_order_and_layout() {
        let mut run = run();
        let artifacts = run.encrypt_a1(&[0x42; 12]).unwrap();
        let expected_positions = [
            (KitCopyV2::One, KitShareIndexV2::One, 1u8, 1u8),
            (KitCopyV2::One, KitShareIndexV2::Two, 1u8, 2u8),
            (KitCopyV2::Two, KitShareIndexV2::One, 2u8, 1u8),
            (KitCopyV2::Two, KitShareIndexV2::Two, 2u8, 2u8),
        ];
        let mut call = 0usize;
        reset_wiped_bytes();
        let receipt = run
            .emit_two_kit_copies(|page| {
                let (copy, share, copy_byte, share_byte) = expected_positions[call];
                assert_eq!(page.copy(), copy);
                assert_eq!(page.share_index(), share);
                let metadata = page.qr_metadata();
                let owner = KitPrintArtifactV2::try_from_page(page).unwrap();
                let bytes = owner.as_bytes();
                assert_eq!(&bytes[0..4], b"QKKP");
                assert_eq!(bytes[4], 1);
                assert_eq!(bytes[5], copy_byte);
                assert_eq!(bytes[6], share_byte);
                assert_eq!(&bytes[7..39], artifacts.wallet_id.as_slice());
                assert_eq!(bytes[39], metadata.mask);
                for (index, penalty) in metadata.penalties.iter().enumerate() {
                    let start = 40 + index * 4;
                    assert_eq!(&bytes[start..start + 4], penalty.to_le_bytes().as_slice());
                }
                assert!(bytes[72..300].iter().any(|&byte| byte != 0));
                assert!(bytes[300..].iter().any(|&byte| byte != 0));
                call += 1;
                KitPageDispositionV2::Accepted
            })
            .unwrap();
        assert_eq!(call, 4);
        assert_eq!(receipt.wallet_id(), artifacts.wallet_id);
        assert_eq!(wiped_bytes(), 4 * KIT_PRINT_ARTIFACT_BYTES);
    }

    #[test]
    fn qkkp_owner_wipes_during_callback_unwind() {
        let mut run = run();
        run.encrypt_a1(&[0x42; 12]).unwrap();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = run.emit_two_kit_copies(|page| {
                let _owner = KitPrintArtifactV2::try_from_page(page).unwrap();
                panic!("test-only callback unwind");
            });
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), KIT_PRINT_ARTIFACT_BYTES);
    }
}
