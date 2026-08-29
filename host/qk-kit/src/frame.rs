//! Canonical Kit share framing and opaque two-share combination.

use crate::secret::{wipe, Secret};
use crate::sha256::Sha256;
use crate::{FrameMetadata, KitError, RecoveredKitPayload, ShareIndex, FRAME_LEN};

const MAGIC: [u8; 4] = *b"QKKS";
const VERSION: u8 = 1;
const SHARE_LEN: usize = 96;
const CHECKSUM_LEN: usize = 8;
const PREFIX_LEN: usize = FRAME_LEN - CHECKSUM_LEN;
const INDEX_OFFSET: usize = 5;
const WALLET_OFFSET: usize = 6;
const SHARE_OFFSET: usize = WALLET_OFFSET + 32;
const CHECKSUM_OFFSET: usize = SHARE_OFFSET + SHARE_LEN;
const CHECKSUM_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";

const _: () = assert!(PREFIX_LEN == 134);
const _: () = assert!(CHECKSUM_OFFSET == PREFIX_LEN);

/// Validated private share owner available only to sibling codec modules.
pub(crate) struct ValidatedShare {
    metadata: FrameMetadata,
    share: Secret<SHARE_LEN>,
}

impl ValidatedShare {
    pub(crate) const fn metadata(&self) -> FrameMetadata {
        self.metadata
    }

    pub(crate) fn share(&self) -> &[u8; SHARE_LEN] {
        self.share.as_bytes()
    }
}

/// Encode one canonical frame from exact caller-owned fixed-size facts.
pub fn encode_frame(
    share_index: ShareIndex,
    wallet_id: &[u8; 32],
    share: &[u8; SHARE_LEN],
) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[INDEX_OFFSET] = share_index.as_u8();
    frame[WALLET_OFFSET..SHARE_OFFSET].copy_from_slice(wallet_id);
    frame[SHARE_OFFSET..CHECKSUM_OFFSET].copy_from_slice(share);

    let mut digest = frame_digest(&frame[..PREFIX_LEN]);
    frame[CHECKSUM_OFFSET..].copy_from_slice(&digest[..CHECKSUM_LEN]);
    wipe(&mut digest);
    frame
}

/// Validate one frame and return only its authenticated public metadata.
pub fn frame_metadata(frame: &[u8]) -> Result<FrameMetadata, KitError> {
    let validated = validate(frame)?;
    Ok(validated.metadata())
}

/// Validate and combine exactly one opposite-index same-wallet pair.
///
/// The left frame is fully validated before the right. Pair rejections then
/// follow exact duplicate, same index, and wallet mismatch precedence.
pub fn combine_frames(
    left_frame: &[u8],
    right_frame: &[u8],
) -> Result<RecoveredKitPayload, KitError> {
    let left = validate(left_frame)?;
    let right = validate(right_frame)?;

    if left_frame == right_frame {
        return Err(KitError::DuplicateShare);
    }
    if left.metadata.share_index == right.metadata.share_index {
        return Err(KitError::SameShareIndex);
    }
    if left.metadata.wallet_id != right.metadata.wallet_id {
        return Err(KitError::WalletMismatch);
    }

    let (one, two) = if left.metadata.share_index == ShareIndex::One {
        (&left, &right)
    } else {
        (&right, &left)
    };
    debug_assert_eq!(one.metadata.share_index, ShareIndex::One);
    debug_assert_eq!(two.metadata.share_index, ShareIndex::Two);

    let mut payload = [0u8; SHARE_LEN];
    for (output, (&one_byte, &two_byte)) in payload
        .iter_mut()
        .zip(one.share().iter().zip(two.share().iter()))
    {
        *output = one_byte ^ two_byte;
    }
    Ok(RecoveredKitPayload::take(&mut payload))
}

/// Validate one canonical frame without releasing its private share bytes.
pub(crate) fn validate(frame: &[u8]) -> Result<ValidatedShare, KitError> {
    if frame.len() != FRAME_LEN {
        return Err(KitError::FrameLength);
    }

    let mut expected = frame_digest(&frame[..PREFIX_LEN]);
    let checksum_matches = constant_time_eq(&expected[..CHECKSUM_LEN], &frame[CHECKSUM_OFFSET..]);
    wipe(&mut expected);
    if !checksum_matches {
        return Err(KitError::FrameChecksum);
    }
    if frame[..4] != MAGIC {
        return Err(KitError::InvalidMagic);
    }
    if frame[4] != VERSION {
        return Err(KitError::UnsupportedVersion);
    }
    let share_index = ShareIndex::parse(frame[INDEX_OFFSET])?;

    let mut wallet_id = [0u8; 32];
    wallet_id.copy_from_slice(&frame[WALLET_OFFSET..SHARE_OFFSET]);
    let mut share = [0u8; SHARE_LEN];
    share.copy_from_slice(&frame[SHARE_OFFSET..CHECKSUM_OFFSET]);
    let owned_share = Secret::copy_from(&share);
    wipe(&mut share);

    Ok(ValidatedShare {
        metadata: FrameMetadata {
            share_index,
            wallet_id,
        },
        share: owned_share,
    })
}

fn frame_digest(prefix: &[u8]) -> [u8; 32] {
    debug_assert_eq!(prefix.len(), PREFIX_LEN);
    let mut digest = [0u8; 32];
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(&[0]);
    hash.update(prefix);
    hash.finish(&mut digest);
    digest
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    debug_assert_eq!(left.len(), right.len());
    let mut difference = 0u8;
    for (&left_byte, &right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{frame_digest, validate, CHECKSUM_OFFSET};
    use crate::{combine_frames, encode_frame, KitError, ShareIndex};

    const FIXTURE: &str = include_str!("../tests/fixtures/kit_share_v2.txt");

    fn field(name: &str) -> &str {
        let prefix = format!("{name}: ");
        FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .expect("fixture field")
    }

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (index, slot) in output.iter_mut().enumerate() {
            let pair = &value.as_bytes()[index * 2..index * 2 + 2];
            *slot = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        output
    }

    fn reseal(frame: &mut [u8; 142]) {
        let digest = frame_digest(&frame[..CHECKSUM_OFFSET]);
        frame[CHECKSUM_OFFSET..].copy_from_slice(&digest[..8]);
    }

    #[test]
    fn frame_rejection_precedence_is_exact() {
        let wallet_id = [0x11u8; 32];
        let share = [0x22u8; 96];
        let valid = encode_frame(ShareIndex::One, &wallet_id, &share);
        assert_eq!(validate(&valid[..141]).err(), Some(KitError::FrameLength));

        let mut candidate = valid;
        candidate[0] ^= 1;
        assert_eq!(validate(&candidate).err(), Some(KitError::FrameChecksum));
        reseal(&mut candidate);
        assert_eq!(validate(&candidate).err(), Some(KitError::InvalidMagic));

        candidate = valid;
        candidate[4] = 2;
        reseal(&mut candidate);
        assert_eq!(
            validate(&candidate).err(),
            Some(KitError::UnsupportedVersion)
        );

        candidate = valid;
        candidate[5] = 3;
        reseal(&mut candidate);
        assert_eq!(
            validate(&candidate).err(),
            Some(KitError::InvalidShareIndex)
        );
    }

    #[test]
    fn combination_normalizes_indices_and_owns_the_exact_xor() {
        let frame_one = hex::<142>(field("frame_1_hex"));
        let frame_two = hex::<142>(field("frame_2_hex"));
        let owned_payload = hex::<96>(field("owned_payload_hex"));
        assert_eq!(owned_payload, hex::<96>(field("combined_payload_hex")));
        let forward = combine_frames(&frame_one, &frame_two).unwrap();
        let reverse = combine_frames(&frame_two, &frame_one).unwrap();
        assert_eq!(forward._bytes.as_bytes(), &owned_payload);
        assert_eq!(reverse._bytes.as_bytes(), &owned_payload);
    }
}
